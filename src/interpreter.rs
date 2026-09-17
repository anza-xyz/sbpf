#![allow(clippy::arithmetic_side_effects)]
// Derived from uBPF <https://github.com/iovisor/ubpf>
// Copyright 2015 Big Switch Networks, Inc
//      (uBPF: VM architecture, parts of the interpreter, originally in C)
// Copyright 2016 6WIND S.A. <quentin.monnet@6wind.com>
//      (Translation to Rust, MetaBuff/multiple classes addition, hashmaps for syscalls)
// Copyright 2020 Solana Maintainers <maintainers@solana.com>
//
// Licensed under the Apache License, Version 2.0 <http://www.apache.org/licenses/LICENSE-2.0> or
// the MIT license <http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

//! Interpreter for eBPF programs.

use crate::{
    ebpf,
    elf::Executable,
    error::{EbpfError, ProgramResult},
    program::BuiltinFunction,
    vm::{CallFrame, Config, ContextObject, EbpfVm},
};

/// Virtual memory operation helper.
macro_rules! translate_memory_access {
    (_impl, $self:ident, $op:ident, $vm_addr:ident, $T:ty, $($rest:expr),*) => {
        match $self.vm.memory().$op::<$T>(
            $($rest,)*
            $vm_addr,
        ) {
            ProgramResult::Ok(v) => v,
            ProgramResult::Err(err) => {
                throw_error!($self, err);
            },
        }
    };


    // MemoryMapping::load()
    ($self:ident, load, $vm_addr:ident, $T:ty) => {{
        let _wl_val = translate_memory_access!(_impl, $self, load, $vm_addr, $T,);
        if let Some(wla) = $self.watch_load_addr {
            let sz = std::mem::size_of::<$T>() as u64;
            if $vm_addr < wla.wrapping_add(8) && $vm_addr.wrapping_add(sz) > wla {
                eprintln!("[SBPF_WATCH_LOAD] LOAD {}B @ 0x{:x} val=0x{:x} PC={} insn#{}",
                    sz, $vm_addr, _wl_val as u64, $self.reg[11], $self.trace_pos.saturating_sub(1));
                for i in 0..12u8 {
                    let name = if i == 10 { "sp".to_string() } else if i == 11 { "pc".to_string() } else { format!("r{}", i) };
                    eprintln!("[SBPF_WATCH_LOAD]   {:>3} = 0x{:016x}", name, $self.reg[i as usize]);
                }
            }
        }
        if $self.vm.trace_config.trace_mem {
            let _tc = &$self.vm.trace_config;
            let passes_program_filter = _tc
                .trace_filter_program_id
                .map_or(true, |filter_pid| filter_pid == _tc.current_program_id);
            if passes_program_filter && _tc.target_program_addr.map_or(true, |t| t == $self.program_vm_addr) {
                let _sz = std::mem::size_of::<$T>() as u8;
                let _do_read = _tc.trace_mem_read || (!_tc.trace_mem_read && !_tc.trace_mem_write);
                if _do_read
                    && (_tc.trace_mem_sizes.is_empty() || _tc.trace_mem_sizes.contains(&_sz))
                {
                    let (acct_idx, acct_off) = $self.resolve_account_addr($vm_addr);
                    let want = _tc.trace_mem_account_idx;
                    let offset_ok = acct_off.map_or(true, |off| {
                        let lo = _tc.trace_mem_offset_start.unwrap_or(0);
                        let hi = _tc.trace_mem_offset_end.unwrap_or(u64::MAX);
                        off >= lo && off < hi
                    });
                    let _pc_range_ok = _tc.trace_pc_range
                        .map_or(true, |(start, end)| $self.reg[11] >= start && $self.reg[11] <= end);
                    let _func_filter_ok = _tc.trace_function_pc
                        .map_or(true, |fp| $self.current_function_pc() == fp);
                    let _load_val = _wl_val as u64;
                    let _val_ok = _tc.trace_mem_value_match.map_or(true, |mv| mv == _load_val);
                    if (want.is_none() || acct_idx == want) && offset_ok && _pc_range_ok && _func_filter_ok && _val_ok {
                        let _regs = if _tc.capture_regs_on_mem_match { Some($self.reg) } else { None };
                        let entry = crate::vm::MemTraceEntry {
                            pc: $self.reg[11],
                            program_id: $self.vm.trace_config.current_program_id,
                            is_store: false,
                            size: _sz,
                            vm_addr: $vm_addr,
                            value: _load_val,
                            account_idx: acct_idx,
                            account_offset: acct_off,
                            function_pc: $self.current_function_pc(),
                            call_depth: $self.vm.call_depth,
                            regs: _regs,
                        };
                        if $self.vm.trace_config.trace_stream {
                            $self.vm.mem_trace.push(entry.clone());
                            crate::vm::TraceEvent::MemAccess(entry).stream_print();
                        } else {
                            $self.vm.mem_trace.push(entry);
                        }
                    }
                }
            }
        }
        _wl_val
    }};

    // MemoryMapping::store()
    ($self:ident, store, $value:expr, $vm_addr:ident, $T:ty) => {{
        translate_memory_access!(_impl, $self, store, $vm_addr, $T, ($value) as $T);
        if let Some((ws, we)) = $self.watch_range {
            let sz = std::mem::size_of::<$T>() as u64;
            if $vm_addr < we && $vm_addr.wrapping_add(sz) > ws {
                eprintln!("[SBPF_WATCH] STORE {}B @ 0x{:x} val=0x{:x} PC={} insn#{}",
                    sz, $vm_addr, ($value) as u64, $self.reg[11], $self.trace_pos.saturating_sub(1));
                for i in 0..12u8 {
                    let name = if i == 10 { "sp".to_string() } else if i == 11 { "pc".to_string() } else { format!("r{}", i) };
                    eprintln!("[SBPF_WATCH]   {:>3} = 0x{:016x}", name, $self.reg[i as usize]);
                }
            }
        }
        if $self.vm.trace_config.trace_mem {
            let _tc = &$self.vm.trace_config;
            let passes_program_filter = _tc
                .trace_filter_program_id
                .map_or(true, |filter_pid| filter_pid == _tc.current_program_id);
            if passes_program_filter && _tc.target_program_addr.map_or(true, |t| t == $self.program_vm_addr) {
                let _sz = std::mem::size_of::<$T>() as u8;
                let _do_write = _tc.trace_mem_write || (!_tc.trace_mem_read && !_tc.trace_mem_write);
                if _do_write
                    && (_tc.trace_mem_sizes.is_empty() || _tc.trace_mem_sizes.contains(&_sz))
                {
                    let (acct_idx, acct_off) = $self.resolve_account_addr($vm_addr);
                    let want = _tc.trace_mem_account_idx;
                    let offset_ok = acct_off.map_or(true, |off| {
                        let lo = _tc.trace_mem_offset_start.unwrap_or(0);
                        let hi = _tc.trace_mem_offset_end.unwrap_or(u64::MAX);
                        off >= lo && off < hi
                    });
                    let _store_pc_range_ok = _tc.trace_pc_range
                        .map_or(true, |(start, end)| $self.reg[11] >= start && $self.reg[11] <= end);
                    let _store_func_filter_ok = _tc.trace_function_pc
                        .map_or(true, |fp| $self.current_function_pc() == fp);
                    let _store_val = ($value) as u64;
                    let _store_val_ok = _tc.trace_mem_value_match.map_or(true, |mv| mv == _store_val);
                    if (want.is_none() || acct_idx == want) && offset_ok && _store_pc_range_ok && _store_func_filter_ok && _store_val_ok {
                        let _regs = if _tc.capture_regs_on_mem_match { Some($self.reg) } else { None };
                        let entry = crate::vm::MemTraceEntry {
                            pc: $self.reg[11],
                            program_id: $self.vm.trace_config.current_program_id,
                            is_store: true,
                            size: _sz,
                            vm_addr: $vm_addr,
                            value: _store_val,
                            account_idx: acct_idx,
                            account_offset: acct_off,
                            function_pc: $self.current_function_pc(),
                            call_depth: $self.vm.call_depth,
                            regs: _regs,
                        };
                        if $self.vm.trace_config.trace_stream {
                            $self.vm.mem_trace.push(entry.clone());
                            crate::vm::TraceEvent::MemAccess(entry).stream_print();
                        } else {
                            $self.vm.mem_trace.push(entry);
                        }
                    }
                }
            }
        }
    }};
}

macro_rules! throw_error {
    ($self:expr, $err:expr) => {{
        $self.vm.registers[11] = $self.reg[11];
        $self.vm.program_result = ProgramResult::Err($err);
        return false;
    }};
    (DivideByZero; $self:expr, $src:expr, $ty:ty) => {
        if $src as $ty == 0 {
            throw_error!($self, EbpfError::DivideByZero);
        }
    };
    (DivideOverflow; $self:expr, $src:expr, $dst:expr, $ty:ty) => {
        if $dst as $ty == <$ty>::MIN && $src as $ty == -1 {
            throw_error!($self, EbpfError::DivideOverflow);
        }
    };
}

macro_rules! check_pc {
    ($self:expr, $next_pc:ident, $target_pc:expr) => {
        if ebpf::is_pc_in_program($self.program, $target_pc as usize) {
            $next_pc = $target_pc;
        } else {
            throw_error!($self, EbpfError::CallOutsideTextSegment);
        }
    };
}
const TRACE_RING_SIZE: usize = 200;
/// State of the interpreter during a debugging session
#[cfg(feature = "debugger")]
pub enum DebugState {
    /// Single step the interpreter
    Step,
    /// Continue execution till the end or till a breakpoint is hit
    Continue,
}
#[derive(Clone, Copy)]
pub(crate) struct TraceEntry {
    pub pc: u64,
    pub opc: u8,
    pub dst: u8,
    pub src: u8,
    pub off: i16,
    pub imm: i64,
    pub regs: [u64; 12],
}

impl Default for TraceEntry {
    fn default() -> Self {
        Self {
            pc: 0,
            opc: 0,
            dst: 0,
            src: 0,
            off: 0,
            imm: 0,
            regs: [0; 12],
        }
    }
}

/// State of an interpreter
pub struct Interpreter<'a, 'b, 'c, C: ContextObject> {
    pub(crate) vm: &'a mut EbpfVm<'b, C>,
    pub(crate) executable: &'a Executable<C>,
    pub(crate) program: &'a [u8],
    pub(crate) program_vm_addr: u64,
    pub(crate) call_frames: &'c mut [CallFrame],

    /// General purpose registers and pc
    pub reg: [u64; 12],

    #[cfg(feature = "debugger")]
    pub(crate) debug_state: DebugState,
    #[cfg(feature = "debugger")]
    pub(crate) breakpoints: Vec<u64>,
    pub(crate) trace_ring: Vec<TraceEntry>,
    pub(crate) trace_pos: usize,
    pub(crate) trace_enabled: bool,
    pub(crate) trace_breakpoints: Vec<u64>,
    pub(crate) trace_filter_addr: Option<u64>,
    pub(crate) trace_filter_len: Option<usize>, // Only trace when program len matches
    pub(crate) watch_range: Option<(u64, u64)>, // (start_inclusive, end_exclusive)
    pub(crate) watch_load_addr: Option<u64>,
    pub(crate) memory_patches: Vec<(u64, u64, u64)>, // (pc, addr, value)
    pub(crate) dump_mem_specs: Vec<(u64, u64, usize)>, // (pc, addr, len)
    pub(crate) trace_live: bool,
    pub(crate) function_pc_stack: Vec<u64>,
    pub(crate) alu_value_match: Option<u64>,
}

impl<'a, 'b, 'c, C: ContextObject> Interpreter<'a, 'b, 'c, C> {
    /// Creates a new interpreter state
    ///
    /// Note: `call_frames` must be large enough to hold the executable
    /// config's `max_call_depth` frames.
    pub fn new(
        vm: &'a mut EbpfVm<'b, C>,
        executable: &'a Executable<C>,
        registers: [u64; 12],
        call_frames: &'c mut [CallFrame],
    ) -> Self {
        let (program_vm_addr, program) = executable.get_text_bytes();
        let alu_match_from_config = vm.trace_config.trace_alu_value_match;
        assert!(
            call_frames.len() >= executable.get_config().max_call_depth,
            "call_frames must be large enough for the maximum call depth"
        );
        Self {
            vm,
            executable,
            program,
            program_vm_addr,
            call_frames,
            reg: registers,
            #[cfg(feature = "debugger")]
            debug_state: DebugState::Continue,
            #[cfg(feature = "debugger")]
            breakpoints: Vec::new(),
            trace_enabled: std::env::var("SBPF_TRACE").is_ok(),
            trace_ring: if std::env::var("SBPF_TRACE").is_ok() {
                vec![TraceEntry::default(); TRACE_RING_SIZE]
            } else {
                Vec::new()
            },
            trace_pos: 0,
            trace_breakpoints: std::env::var("SBPF_TRACE_BP")
                .ok()
                .map(|s| {
                    s.split(',')
                        .filter_map(|v| v.trim().parse::<u64>().ok())
                        .collect()
                })
                .unwrap_or_default(),
            trace_filter_addr: std::env::var("SBPF_TRACE_FILTER_ADDR").ok().and_then(|s| {
                u64::from_str_radix(
                    s.trim().trim_start_matches("0x").trim_start_matches("0X"),
                    16,
                )
                .ok()
            }),
            trace_filter_len: std::env::var("SBPF_TRACE_FILTER_LEN")
                .ok()
                .and_then(|s| s.trim().parse::<usize>().ok()),
            watch_range: std::env::var("SBPF_WATCH_RANGE").ok().and_then(|s| {
                let parts: Vec<&str> = s.splitn(2, ',').collect();
                if parts.len() == 2 {
                    let start = u64::from_str_radix(
                        parts[0]
                            .trim()
                            .trim_start_matches("0x")
                            .trim_start_matches("0X"),
                        16,
                    )
                    .ok()?;
                    let len = u64::from_str_radix(
                        parts[1]
                            .trim()
                            .trim_start_matches("0x")
                            .trim_start_matches("0X"),
                        16,
                    )
                    .ok()?;
                    Some((start, start.wrapping_add(len)))
                } else {
                    None
                }
            }),
            watch_load_addr: std::env::var("SBPF_WATCH_LOAD").ok().and_then(|s| {
                let s = s.trim().trim_start_matches("0x").trim_start_matches("0X");
                u64::from_str_radix(s, 16).ok()
            }),
            memory_patches: std::env::var("SBPF_PATCH")
                .ok()
                .map(|s| {
                    s.split(';')
                        .filter_map(|entry| {
                            let parts: Vec<&str> = entry.split(',').collect();
                            if parts.len() == 3 {
                                let pc = parts[0].trim().parse::<u64>().ok()?;
                                let addr = u64::from_str_radix(
                                    parts[1]
                                        .trim()
                                        .trim_start_matches("0x")
                                        .trim_start_matches("0X"),
                                    16,
                                )
                                .ok()?;
                                let val = u64::from_str_radix(
                                    parts[2]
                                        .trim()
                                        .trim_start_matches("0x")
                                        .trim_start_matches("0X"),
                                    16,
                                )
                                .ok()?;
                                Some((pc, addr, val))
                            } else {
                                None
                            }
                        })
                        .collect()
                })
                .unwrap_or_default(),
            dump_mem_specs: std::env::var("SBPF_DUMP_MEM")
                .ok()
                .map(|s| {
                    s.split(';')
                        .filter_map(|entry| {
                            let parts: Vec<&str> = entry.split(',').collect();
                            if parts.len() == 3 {
                                let pc = parts[0].trim().parse::<u64>().ok()?;
                                let addr = u64::from_str_radix(
                                    parts[1]
                                        .trim()
                                        .trim_start_matches("0x")
                                        .trim_start_matches("0X"),
                                    16,
                                )
                                .ok()?;
                                let len = parts[2].trim().parse::<usize>().ok()?;
                                Some((pc, addr, len))
                            } else {
                                None
                            }
                        })
                        .collect()
                })
                .unwrap_or_default(),
            trace_live: std::env::var("SBPF_TRACE_LIVE").is_ok(),
            function_pc_stack: vec![0],
            alu_value_match: alu_match_from_config.or_else(|| {
                std::env::var("SBPF_ALU_VALUE_MATCH").ok().and_then(|s| {
                    let s = s.trim().trim_start_matches("0x").trim_start_matches("0X");
                    u64::from_str_radix(s, 16)
                        .ok()
                        .or_else(|| s.parse::<u64>().ok())
                })
            }),
        }
    }
    #[inline(always)]
    fn current_function_pc(&self) -> u64 {
        *self.function_pc_stack.last().unwrap_or(&0)
    }

    /// Translate between the virtual machines' pc value and the pc value used by the debugger
    #[cfg(feature = "debugger")]
    pub fn get_dbg_pc(&self) -> u64 {
        (self.reg[11] * ebpf::INSN_SIZE as u64) + self.executable.get_text_section_offset()
    }

    fn classify_opcode(opc: u8) -> Option<(&'static str, &'static str)> {
        use crate::ebpf;
        match opc {
            // ALU 32
            ebpf::ADD32_IMM => Some(("alu", "ADD32_IMM")),
            ebpf::ADD32_REG => Some(("alu", "ADD32_REG")),
            ebpf::SUB32_IMM => Some(("alu", "SUB32_IMM")),
            ebpf::SUB32_REG => Some(("alu", "SUB32_REG")),
            ebpf::MUL32_IMM => Some(("alu", "MUL32_IMM")),
            ebpf::MUL32_REG => Some(("alu", "MUL32_REG")),
            ebpf::DIV32_IMM => Some(("alu", "DIV32_IMM")),
            ebpf::DIV32_REG => Some(("alu", "DIV32_REG")),
            ebpf::OR32_IMM => Some(("alu", "OR32_IMM")),
            ebpf::OR32_REG => Some(("alu", "OR32_REG")),
            ebpf::AND32_IMM => Some(("alu", "AND32_IMM")),
            ebpf::AND32_REG => Some(("alu", "AND32_REG")),
            ebpf::LSH32_IMM => Some(("alu", "LSH32_IMM")),
            ebpf::LSH32_REG => Some(("alu", "LSH32_REG")),
            ebpf::RSH32_IMM => Some(("alu", "RSH32_IMM")),
            ebpf::RSH32_REG => Some(("alu", "RSH32_REG")),
            ebpf::NEG32 => Some(("alu", "NEG32")),
            ebpf::MOD32_IMM => Some(("alu", "MOD32_IMM")),
            ebpf::MOD32_REG => Some(("alu", "MOD32_REG")),
            ebpf::XOR32_IMM => Some(("alu", "XOR32_IMM")),
            ebpf::XOR32_REG => Some(("alu", "XOR32_REG")),
            ebpf::MOV32_IMM => Some(("alu", "MOV32_IMM")),
            ebpf::MOV32_REG => Some(("alu", "MOV32_REG")),
            ebpf::ARSH32_IMM => Some(("alu", "ARSH32_IMM")),
            ebpf::ARSH32_REG => Some(("alu", "ARSH32_REG")),
            // ALU 64
            ebpf::ADD64_IMM => Some(("alu", "ADD64_IMM")),
            ebpf::ADD64_REG => Some(("alu", "ADD64_REG")),
            ebpf::SUB64_IMM => Some(("alu", "SUB64_IMM")),
            ebpf::SUB64_REG => Some(("alu", "SUB64_REG")),
            ebpf::MUL64_IMM => Some(("alu", "MUL64_IMM")),
            ebpf::MUL64_REG => Some(("alu", "MUL64_REG")),
            ebpf::DIV64_IMM => Some(("alu", "DIV64_IMM")),
            ebpf::DIV64_REG => Some(("alu", "DIV64_REG")),
            ebpf::OR64_IMM => Some(("alu", "OR64_IMM")),
            ebpf::OR64_REG => Some(("alu", "OR64_REG")),
            ebpf::AND64_IMM => Some(("alu", "AND64_IMM")),
            ebpf::AND64_REG => Some(("alu", "AND64_REG")),
            ebpf::LSH64_IMM => Some(("alu", "LSH64_IMM")),
            ebpf::LSH64_REG => Some(("alu", "LSH64_REG")),
            ebpf::RSH64_IMM => Some(("alu", "RSH64_IMM")),
            ebpf::RSH64_REG => Some(("alu", "RSH64_REG")),
            ebpf::NEG64 => Some(("alu", "NEG64")),
            ebpf::MOD64_IMM => Some(("alu", "MOD64_IMM")),
            ebpf::MOD64_REG => Some(("alu", "MOD64_REG")),
            ebpf::XOR64_IMM => Some(("alu", "XOR64_IMM")),
            ebpf::XOR64_REG => Some(("alu", "XOR64_REG")),
            ebpf::MOV64_IMM => Some(("alu", "MOV64_IMM")),
            ebpf::MOV64_REG => Some(("alu", "MOV64_REG")),
            ebpf::ARSH64_IMM => Some(("alu", "ARSH64_IMM")),
            ebpf::ARSH64_REG => Some(("alu", "ARSH64_REG")),
            ebpf::LE => Some(("alu", "LE")),
            ebpf::BE => Some(("alu", "BE")),
            // JMP32 (new in sbpf-main)
            ebpf::JEQ32_IMM => Some(("jump", "JEQ32_IMM")),
            ebpf::JEQ32_REG => Some(("jump", "JEQ32_REG")),
            ebpf::JGT32_IMM => Some(("jump", "JGT32_IMM")),
            ebpf::JGT32_REG => Some(("jump", "JGT32_REG")),
            ebpf::JGE32_IMM => Some(("jump", "JGE32_IMM")),
            ebpf::JGE32_REG => Some(("jump", "JGE32_REG")),
            ebpf::JLT32_IMM => Some(("jump", "JLT32_IMM")),
            ebpf::JLT32_REG => Some(("jump", "JLT32_REG")),
            ebpf::JLE32_IMM => Some(("jump", "JLE32_IMM")),
            ebpf::JLE32_REG => Some(("jump", "JLE32_REG")),
            ebpf::JSET32_IMM => Some(("jump", "JSET32_IMM")),
            ebpf::JSET32_REG => Some(("jump", "JSET32_REG")),
            ebpf::JNE32_IMM => Some(("jump", "JNE32_IMM")),
            ebpf::JNE32_REG => Some(("jump", "JNE32_REG")),
            ebpf::JSGT32_IMM => Some(("jump", "JSGT32_IMM")),
            ebpf::JSGT32_REG => Some(("jump", "JSGT32_REG")),
            ebpf::JSGE32_IMM => Some(("jump", "JSGE32_IMM")),
            ebpf::JSGE32_REG => Some(("jump", "JSGE32_REG")),
            ebpf::JSLT32_IMM => Some(("jump", "JSLT32_IMM")),
            ebpf::JSLT32_REG => Some(("jump", "JSLT32_REG")),
            ebpf::JSLE32_IMM => Some(("jump", "JSLE32_IMM")),
            ebpf::JSLE32_REG => Some(("jump", "JSLE32_REG")),
            // JMP64 (renamed from JMP)
            ebpf::JA => Some(("jump", "JA")),
            ebpf::JEQ64_IMM => Some(("jump", "JEQ64_IMM")),
            ebpf::JEQ64_REG => Some(("jump", "JEQ64_REG")),
            ebpf::JGT64_IMM => Some(("jump", "JGT64_IMM")),
            ebpf::JGT64_REG => Some(("jump", "JGT64_REG")),
            ebpf::JGE64_IMM => Some(("jump", "JGE64_IMM")),
            ebpf::JGE64_REG => Some(("jump", "JGE64_REG")),
            ebpf::JLT64_IMM => Some(("jump", "JLT64_IMM")),
            ebpf::JLT64_REG => Some(("jump", "JLT64_REG")),
            ebpf::JLE64_IMM => Some(("jump", "JLE64_IMM")),
            ebpf::JLE64_REG => Some(("jump", "JLE64_REG")),
            ebpf::JSET64_IMM => Some(("jump", "JSET64_IMM")),
            ebpf::JSET64_REG => Some(("jump", "JSET64_REG")),
            ebpf::JNE64_IMM => Some(("jump", "JNE64_IMM")),
            ebpf::JNE64_REG => Some(("jump", "JNE64_REG")),
            ebpf::JSGT64_IMM => Some(("jump", "JSGT64_IMM")),
            ebpf::JSGT64_REG => Some(("jump", "JSGT64_REG")),
            ebpf::JSGE64_IMM => Some(("jump", "JSGE64_IMM")),
            ebpf::JSGE64_REG => Some(("jump", "JSGE64_REG")),
            ebpf::JSLT64_IMM => Some(("jump", "JSLT64_IMM")),
            ebpf::JSLT64_REG => Some(("jump", "JSLT64_REG")),
            ebpf::JSLE64_IMM => Some(("jump", "JSLE64_IMM")),
            ebpf::JSLE64_REG => Some(("jump", "JSLE64_REG")),
            // calls
            ebpf::CALL_IMM => Some(("call", "CALL_IMM")),
            ebpf::CALL_REG => Some(("call", "CALL_REG")),
            ebpf::EXIT => Some(("call", "EXIT")), // replaces RETURN+SYSCALL
            _ => None,
        }
    }

    fn resolve_account_addr(&self, vm_addr: u64) -> (Option<usize>, Option<u64>) {
        for r in &self.vm.trace_config.account_ranges {
            if vm_addr >= r.vm_start && vm_addr < r.vm_end {
                return (Some(r.account_idx), Some(vm_addr - r.vm_start));
            }
        }
        (None, None)
    }

    fn push_frame(&mut self, config: &Config) -> bool {
        let frame = &mut self.call_frames[self.vm.call_depth as usize];
        frame.caller_saved_registers.copy_from_slice(
            &self.reg[ebpf::FIRST_SCRATCH_REG..ebpf::FIRST_SCRATCH_REG + ebpf::SCRATCH_REGS],
        );
        frame.frame_pointer = self.reg[ebpf::FRAME_PTR_REG];
        frame.target_pc = self.reg[11] + 1;

        self.vm.call_depth += 1;
        if self.vm.call_depth as usize == config.max_call_depth {
            throw_error!(self, EbpfError::CallDepthExceeded);
        }

        if !self.executable.get_sbpf_version().manual_stack_frame_bump() {
            // With fixed frames we start the new frame at the next fixed offset
            let num_frames = if self.executable.get_sbpf_version().stack_frame_gaps()
                && config.enable_stack_frame_gaps
            {
                2
            } else {
                1
            };
            let stack_frame_size = config.stack_frame_size * num_frames;
            self.reg[ebpf::FRAME_PTR_REG] =
                self.reg[ebpf::FRAME_PTR_REG].wrapping_add(stack_frame_size as u64);
        }

        true
    }

    fn sign_extension(&self, value: i32) -> u64 {
        if self
            .executable
            .get_sbpf_version()
            .explicit_sign_extension_of_results()
        {
            value as u32 as u64
        } else {
            value as i64 as u64
        }
    }

    /// Advances the interpreter state by one instruction
    ///
    /// Returns false if the program terminated or threw an error.
    #[rustfmt::skip]
    #[inline(always)]
    pub fn step(&mut self) -> bool {
        let config = &self.executable.get_config();

        if config.enable_instruction_meter && self.vm.due_insn_count >= self.vm.previous_instruction_meter {
            throw_error!(self, EbpfError::ExceededMaxInstructions);
        }
        self.vm.due_insn_count += 1;
        if self.reg[11] as usize * ebpf::INSN_SIZE >= self.program.len() {
            throw_error!(self, EbpfError::ExecutionOverrun);
        }
        let mut next_pc = self.reg[11] + 1;
        let mut insn = ebpf::get_insn_unchecked(self.program, self.reg[11] as usize);
        let dst = insn.dst as usize;
        let src = insn.src as usize;

        if config.enable_register_tracing {
            self.vm.register_trace.push(self.reg);
        }
        // Memory patch: write a value to a specific address when PC matches
        for (patch_pc, patch_addr, patch_val) in &self.memory_patches {
            if self.reg[11] == *patch_pc {
                let _ = self.vm.memory().store::<u64>(*patch_val, *patch_addr);
                eprintln!(
                    "[SBPF_PATCH] Wrote 0x{:x} to 0x{:x} at PC={}",
                    patch_val, patch_addr, patch_pc
                );
            }
        }
        for (dump_pc, dump_addr, dump_len) in &self.dump_mem_specs {
            if self.reg[11] == *dump_pc {
                let mut bytes = Vec::with_capacity(*dump_len);
                let mut read_ok = true;
                for i in 0..*dump_len as u64 {
                    match self.vm.memory().load::<u8>(*dump_addr + i) {
                        ProgramResult::Ok(b) => bytes.push(b as u8),
                        _ => { read_ok = false; break; }
                    }
                }
                if read_ok {
                    eprintln!("[SBPF_DUMP_MEM] PC={} addr=0x{:x} len={}: {:02x?}", dump_pc, dump_addr, dump_len, &bytes);
                    let passes_program_filter = self
                        .vm
                        .trace_config
                        .trace_filter_program_id
                        .map_or(true, |filter_pid| {
                            filter_pid == self.vm.trace_config.current_program_id
                        });
                    if passes_program_filter {
                        let entry = crate::vm::MemDumpResult {
                            pc: *dump_pc,
                            program_id: self.vm.trace_config.current_program_id,
                            vm_addr: *dump_addr,
                            bytes: bytes.clone(),
                        };
                        if self.vm.trace_config.trace_stream {
                            self.vm.mem_dump_results.push(entry.clone());
                            crate::vm::TraceEvent::MemDump(entry).stream_print();
                        } else {
                            self.vm.mem_dump_results.push(entry);
                        }
                    }
                } else {
                    eprintln!("[SBPF_DUMP_MEM] PC={} addr=0x{:x} len={}: <partial {:02x?}>", dump_pc, dump_addr, dump_len, &bytes);
                }
            }
        }
        for (dump_pc, dump_addr, dump_len) in self.vm.trace_config.dump_mem_specs.clone() {
            if self.reg[11] == dump_pc {
                let mut bytes = Vec::with_capacity(dump_len as usize);
                let mut read_ok = true;
                for i in 0..dump_len {
                    match self.vm.memory().load::<u8>(dump_addr + i) {
                        ProgramResult::Ok(b) => bytes.push(b as u8),
                        _ => { read_ok = false; break; }
                    }
                }
                if read_ok {
                    let passes_program_filter = self
                        .vm
                        .trace_config
                        .trace_filter_program_id
                        .map_or(true, |filter_pid| {
                            filter_pid == self.vm.trace_config.current_program_id
                        });
                    if passes_program_filter {
                        let entry = crate::vm::MemDumpResult {
                            pc: dump_pc,
                            program_id: self.vm.trace_config.current_program_id,
                            vm_addr: dump_addr,
                            bytes,
                        };
                        if self.vm.trace_config.trace_stream {
                            self.vm.mem_dump_results.push(entry.clone());
                            crate::vm::TraceEvent::MemDump(entry).stream_print();
                        } else {
                            self.vm.mem_dump_results.push(entry);
                        }
                    }
                }
            }
        }
        for &snap_pc in &self.vm.trace_config.trace_regs_at_pcs.clone() {
            if self.reg[11] == snap_pc {
                let passes_program_filter = self
                    .vm
                    .trace_config
                    .trace_filter_program_id
                    .map_or(true, |filter_pid| filter_pid == self.vm.trace_config.current_program_id);
                if passes_program_filter {
                    let entry = crate::vm::RegSnapshot {
                        pc: snap_pc,
                        program_id: self.vm.trace_config.current_program_id,
                        regs: self.reg,
                    };
                    if self.vm.trace_config.trace_stream {
                        self.vm.reg_snapshots.push(entry.clone());
                        crate::vm::TraceEvent::RegSnapshot(entry).stream_print();
                    } else {
                        self.vm.reg_snapshots.push(entry);
                    }
                }
            }
        }

        let should_trace = self.trace_enabled
            && self
                .trace_filter_addr
                .map_or(true, |filter| filter == self.program_vm_addr)
            && self
                .trace_filter_len
                .map_or(true, |filter| filter == self.program.len());

        if should_trace {
            let idx = self.trace_pos % TRACE_RING_SIZE;
            self.trace_ring[idx] = TraceEntry {
                pc: self.reg[11],
                opc: insn.opc,
                dst: insn.dst,
                src: insn.src,
                off: insn.off,
                imm: insn.imm,
                regs: self.reg,
            };
            self.trace_pos += 1;

            if self.trace_live {
                let opc = insn.opc;
                let is_call_or_jump = matches!(opc,
                    // JMP64 (0x05 class)
                    0x05 | 0x15 | 0x1d | 0x25 | 0x2d | 0x35 | 0x3d |
                    0x45 | 0x4d | 0x55 | 0x5d | 0x65 | 0x6d |
                    0xa5 | 0xad | 0xb5 | 0xbd |
                    // JMP32 (0x06 class) - new in sbpf-main
                    0x16 | 0x1e | 0x26 | 0x2e | 0x36 | 0x3e |
                    0x46 | 0x4e | 0x56 | 0x5e | 0x66 | 0x6e |
                    0xa6 | 0xae | 0xb6 | 0xbe |
                    // calls
                    0x85 | 0x95
                );
                if is_call_or_jump {
                    eprintln!(
                        "[SBPF_LIVE] prog=0x{:x} {:>6} PC={:<6} off=0x{:<8x} opc=0x{:02x} dst=r{} src=r{} off={:<6} imm=0x{:<8x} | r0=0x{:x} r1=0x{:x} r2=0x{:x} r3=0x{:x} r4=0x{:x} r5=0x{:x}",
                        self.program_vm_addr, self.trace_pos, self.reg[11],
                        self.reg[11] * 8, opc, insn.dst, insn.src, insn.off, insn.imm as u64,
                        self.reg[0], self.reg[1], self.reg[2], self.reg[3], self.reg[4], self.reg[5],
                    );
                }
            }

            if self.trace_breakpoints.contains(&self.reg[11]) {
                self.dump_breakpoint_hit();
            }
        }

        let _pc_range_ok = self.vm.trace_config.trace_pc_range
            .map_or(true, |(start, end)| self.reg[11] >= start && self.reg[11] <= end);
        let _func_filter_ok = self.vm.trace_config.trace_function_pc
            .map_or(true, |fp| self.current_function_pc() == fp);
        let _insn_trace_active = self.vm.trace_config.trace_insn
            && self.vm.trace_config.target_program_addr.map_or(true, |t| t == self.program_vm_addr)
            && _pc_range_ok
            && _func_filter_ok;
        let _insn_dst_before = self.reg[dst];
        let _insn_src_val = self.reg[src];
        let _insn_old_next_pc = next_pc;

        match insn.opc {
            ebpf::LD_DW_IMM if !self.executable.get_sbpf_version().disable_lddw() => {
                ebpf::augment_lddw_unchecked(self.program, &mut insn);
                self.reg[dst] = insn.imm as u64;
                self.reg[11] += 1;
                next_pc += 1;
            },

            // BPF_LDX class
            ebpf::LD_B_REG  if !self.executable.get_sbpf_version().move_memory_instruction_classes() => {
                let vm_addr = (self.reg[src] as i64).wrapping_add(insn.off as i64) as u64;
                self.reg[dst] = translate_memory_access!(self, load, vm_addr, u8);
            },
            ebpf::LD_H_REG  if !self.executable.get_sbpf_version().move_memory_instruction_classes() => {
                let vm_addr = (self.reg[src] as i64).wrapping_add(insn.off as i64) as u64;
                self.reg[dst] = translate_memory_access!(self, load, vm_addr, u16);
            },
            ebpf::LD_W_REG  if !self.executable.get_sbpf_version().move_memory_instruction_classes() => {
                let vm_addr = (self.reg[src] as i64).wrapping_add(insn.off as i64) as u64;
                self.reg[dst] = translate_memory_access!(self, load, vm_addr, u32);
            },
            ebpf::LD_DW_REG if !self.executable.get_sbpf_version().move_memory_instruction_classes() => {
                let vm_addr = (self.reg[src] as i64).wrapping_add(insn.off as i64) as u64;
                self.reg[dst] = translate_memory_access!(self, load, vm_addr, u64);
            },

            // BPF_ST class
            ebpf::ST_B_IMM  if !self.executable.get_sbpf_version().move_memory_instruction_classes() => {
                let vm_addr = (self.reg[dst] as i64).wrapping_add(insn.off as i64) as u64;
                translate_memory_access!(self, store, insn.imm, vm_addr, u8);
            },
            ebpf::ST_H_IMM  if !self.executable.get_sbpf_version().move_memory_instruction_classes() => {
                let vm_addr = (self.reg[dst] as i64).wrapping_add(insn.off as i64) as u64;
                translate_memory_access!(self, store, insn.imm, vm_addr, u16);
            },
            ebpf::ST_W_IMM  if !self.executable.get_sbpf_version().move_memory_instruction_classes() => {
                let vm_addr = (self.reg[dst] as i64).wrapping_add(insn.off as i64) as u64;
                translate_memory_access!(self, store, insn.imm, vm_addr, u32);
            },
            ebpf::ST_DW_IMM if !self.executable.get_sbpf_version().move_memory_instruction_classes() => {
                let vm_addr = (self.reg[dst] as i64).wrapping_add(insn.off as i64) as u64;
                translate_memory_access!(self, store, insn.imm, vm_addr, u64);
            },

            // BPF_STX class
            ebpf::ST_B_REG  if !self.executable.get_sbpf_version().move_memory_instruction_classes() => {
                let vm_addr = (self.reg[dst] as i64).wrapping_add(insn.off as i64) as u64;
                translate_memory_access!(self, store, self.reg[src], vm_addr, u8);
            },
            ebpf::ST_H_REG  if !self.executable.get_sbpf_version().move_memory_instruction_classes() => {
                let vm_addr = (self.reg[dst] as i64).wrapping_add(insn.off as i64) as u64;
                translate_memory_access!(self, store, self.reg[src], vm_addr, u16);
            },
            ebpf::ST_W_REG  if !self.executable.get_sbpf_version().move_memory_instruction_classes() => {
                let vm_addr = (self.reg[dst] as i64).wrapping_add(insn.off as i64) as u64;
                translate_memory_access!(self, store, self.reg[src], vm_addr, u32);
            },
            ebpf::ST_DW_REG if !self.executable.get_sbpf_version().move_memory_instruction_classes() => {
                let vm_addr = (self.reg[dst] as i64).wrapping_add(insn.off as i64) as u64;
                translate_memory_access!(self, store, self.reg[src], vm_addr, u64);
            },

            // BPF_ALU32_LOAD class
            ebpf::ADD32_IMM  => self.reg[dst] = self.sign_extension((self.reg[dst] as i32).wrapping_add(insn.imm as i32)),
            ebpf::ADD32_REG  => self.reg[dst] = self.sign_extension((self.reg[dst] as i32).wrapping_add(self.reg[src] as i32)),
            ebpf::SUB32_IMM  => if self.executable.get_sbpf_version().swap_sub_reg_imm_operands() {
                                self.reg[dst] = self.sign_extension((insn.imm as i32).wrapping_sub(self.reg[dst] as i32))
            } else {
                                self.reg[dst] = self.sign_extension((self.reg[dst] as i32).wrapping_sub(insn.imm as i32))
            },
            ebpf::SUB32_REG  => self.reg[dst] = self.sign_extension((self.reg[dst] as i32).wrapping_sub(self.reg[src] as i32)),
            ebpf::MUL32_IMM  if !self.executable.get_sbpf_version().enable_pqr() => self.reg[dst] = self.sign_extension((self.reg[dst] as i32).wrapping_mul(insn.imm as i32)     ),
            ebpf::MUL32_REG  if !self.executable.get_sbpf_version().enable_pqr() => self.reg[dst] = self.sign_extension((self.reg[dst] as i32).wrapping_mul(self.reg[src] as i32)),
            ebpf::LD_1B_REG  if self.executable.get_sbpf_version().move_memory_instruction_classes() => {
                let vm_addr = (self.reg[src] as i64).wrapping_add(insn.off as i64) as u64;
                self.reg[dst] = translate_memory_access!(self, load, vm_addr, u8);
            },
            ebpf::DIV32_IMM  if !self.executable.get_sbpf_version().enable_pqr() => self.reg[dst] = (self.reg[dst] as u32             / insn.imm as u32)      as u64,
            ebpf::DIV32_REG  if !self.executable.get_sbpf_version().enable_pqr() => {
                throw_error!(DivideByZero; self, self.reg[src], u32);
                                self.reg[dst] = (self.reg[dst] as u32             / self.reg[src] as u32) as u64;
            },
            ebpf::LD_2B_REG  if self.executable.get_sbpf_version().move_memory_instruction_classes() => {
                let vm_addr = (self.reg[src] as i64).wrapping_add(insn.off as i64) as u64;
                self.reg[dst] = translate_memory_access!(self, load, vm_addr, u16);
            },
            ebpf::OR32_IMM   => self.reg[dst] = (self.reg[dst] as u32             | insn.imm as u32)      as u64,
            ebpf::OR32_REG   => self.reg[dst] = (self.reg[dst] as u32             | self.reg[src] as u32) as u64,
            ebpf::AND32_IMM  => self.reg[dst] = (self.reg[dst] as u32             & insn.imm as u32)      as u64,
            ebpf::AND32_REG  => self.reg[dst] = (self.reg[dst] as u32             & self.reg[src] as u32) as u64,
            ebpf::LSH32_IMM  => self.reg[dst] = (self.reg[dst] as u32).wrapping_shl(insn.imm as u32)      as u64,
            ebpf::LSH32_REG  => self.reg[dst] = (self.reg[dst] as u32).wrapping_shl(self.reg[src] as u32) as u64,
            ebpf::RSH32_IMM  => self.reg[dst] = (self.reg[dst] as u32).wrapping_shr(insn.imm as u32)      as u64,
            ebpf::RSH32_REG  => self.reg[dst] = (self.reg[dst] as u32).wrapping_shr(self.reg[src] as u32) as u64,
            ebpf::NEG32      if !self.executable.get_sbpf_version().disable_neg() => self.reg[dst] = (self.reg[dst] as i32).wrapping_neg()                     as u64 & (u32::MAX as u64),
            ebpf::LD_4B_REG  if self.executable.get_sbpf_version().move_memory_instruction_classes() => {
                let vm_addr = (self.reg[src] as i64).wrapping_add(insn.off as i64) as u64;
                self.reg[dst] = translate_memory_access!(self, load, vm_addr, u32);
            },
            ebpf::MOD32_IMM  if !self.executable.get_sbpf_version().enable_pqr() => self.reg[dst] = (self.reg[dst] as u32             % insn.imm as u32)      as u64,
            ebpf::MOD32_REG  if !self.executable.get_sbpf_version().enable_pqr() => {
                throw_error!(DivideByZero; self, self.reg[src], u32);
                                self.reg[dst] = (self.reg[dst] as u32             % self.reg[src] as u32) as u64;
            },
            ebpf::LD_8B_REG  if self.executable.get_sbpf_version().move_memory_instruction_classes() => {
                let vm_addr = (self.reg[src] as i64).wrapping_add(insn.off as i64) as u64;
                self.reg[dst] = translate_memory_access!(self, load, vm_addr, u64);
            },
            ebpf::XOR32_IMM  => self.reg[dst] = (self.reg[dst] as u32             ^ insn.imm as u32)      as u64,
            ebpf::XOR32_REG  => self.reg[dst] = (self.reg[dst] as u32             ^ self.reg[src] as u32) as u64,
            ebpf::MOV32_IMM  => self.reg[dst] = insn.imm as u32 as u64,
            ebpf::MOV32_REG  => self.reg[dst] = if self.executable.get_sbpf_version().explicit_sign_extension_of_results() {
                self.reg[src] as i32 as i64 as u64
            } else {
                self.reg[src] as u32 as u64
            },
            ebpf::ARSH32_IMM => self.reg[dst] = (self.reg[dst] as i32).wrapping_shr(insn.imm as u32)      as u32 as u64,
            ebpf::ARSH32_REG => self.reg[dst] = (self.reg[dst] as i32).wrapping_shr(self.reg[src] as u32) as u32 as u64,
            ebpf::LE if !self.executable.get_sbpf_version().disable_le() => {
                self.reg[dst] = match insn.imm {
                    16 => (self.reg[dst] as u16).to_le() as u64,
                    32 => (self.reg[dst] as u32).to_le() as u64,
                    64 =>  self.reg[dst].to_le(),
                    _  => {
                        throw_error!(self, EbpfError::InvalidInstruction);
                    }
                };
            },
            ebpf::BE         => {
                self.reg[dst] = match insn.imm {
                    16 => (self.reg[dst] as u16).to_be() as u64,
                    32 => (self.reg[dst] as u32).to_be() as u64,
                    64 =>  self.reg[dst].to_be(),
                    _  => {
                        throw_error!(self, EbpfError::InvalidInstruction);
                    }
                };
            },

            // BPF_ALU64_STORE class
            ebpf::ADD64_IMM  => self.reg[dst] =  self.reg[dst].wrapping_add(insn.imm as u64),
            ebpf::ADD64_REG  => self.reg[dst] =  self.reg[dst].wrapping_add(self.reg[src]),
            ebpf::SUB64_IMM  => if self.executable.get_sbpf_version().swap_sub_reg_imm_operands() {
                                self.reg[dst] =  (insn.imm as u64).wrapping_sub(self.reg[dst])
            } else {
                                self.reg[dst] =  self.reg[dst].wrapping_sub(insn.imm as u64)
            },
            ebpf::SUB64_REG  => self.reg[dst] =  self.reg[dst].wrapping_sub(self.reg[src]),
            ebpf::MUL64_IMM  if !self.executable.get_sbpf_version().enable_pqr() => self.reg[dst] =  self.reg[dst].wrapping_mul(insn.imm as u64),
            ebpf::ST_1B_IMM  if self.executable.get_sbpf_version().move_memory_instruction_classes() => {
                let vm_addr = (self.reg[dst] as i64).wrapping_add(insn.off as i64) as u64;
                translate_memory_access!(self, store, insn.imm, vm_addr, u8);
            },
            ebpf::MUL64_REG  if !self.executable.get_sbpf_version().enable_pqr() => self.reg[dst] =  self.reg[dst].wrapping_mul(self.reg[src]),
            ebpf::ST_1B_REG  if self.executable.get_sbpf_version().move_memory_instruction_classes() => {
                let vm_addr = (self.reg[dst] as i64).wrapping_add(insn.off as i64) as u64;
                translate_memory_access!(self, store, self.reg[src], vm_addr, u8);
            },
            ebpf::DIV64_IMM  if !self.executable.get_sbpf_version().enable_pqr() => self.reg[dst] /= insn.imm as u64,
            ebpf::ST_2B_IMM  if self.executable.get_sbpf_version().move_memory_instruction_classes() => {
                let vm_addr = (self.reg[dst] as i64).wrapping_add(insn.off as i64) as u64;
                translate_memory_access!(self, store, insn.imm, vm_addr, u16);
            },
            ebpf::DIV64_REG  if !self.executable.get_sbpf_version().enable_pqr() => {
                throw_error!(DivideByZero; self, self.reg[src], u64);
                                self.reg[dst] /= self.reg[src];
            },
            ebpf::ST_2B_REG  if self.executable.get_sbpf_version().move_memory_instruction_classes() => {
                let vm_addr = (self.reg[dst] as i64).wrapping_add(insn.off as i64) as u64;
                translate_memory_access!(self, store, self.reg[src], vm_addr, u16);
            },
            ebpf::OR64_IMM   => self.reg[dst] |= insn.imm as u64,
            ebpf::OR64_REG   => self.reg[dst] |= self.reg[src],
            ebpf::AND64_IMM  => self.reg[dst] &= insn.imm as u64,
            ebpf::AND64_REG  => self.reg[dst] &= self.reg[src],
            ebpf::LSH64_IMM  => self.reg[dst] =  self.reg[dst].wrapping_shl(insn.imm as u32),
            ebpf::LSH64_REG  => self.reg[dst] =  self.reg[dst].wrapping_shl(self.reg[src] as u32),
            ebpf::RSH64_IMM  => self.reg[dst] =  self.reg[dst].wrapping_shr(insn.imm as u32),
            ebpf::RSH64_REG  => self.reg[dst] =  self.reg[dst].wrapping_shr(self.reg[src] as u32),
            ebpf::ST_4B_IMM  if self.executable.get_sbpf_version().move_memory_instruction_classes() => {
                let vm_addr = (self.reg[dst] as i64).wrapping_add(insn.off as i64) as u64;
                translate_memory_access!(self, store, insn.imm, vm_addr, u32);
            },
            ebpf::NEG64      if !self.executable.get_sbpf_version().disable_neg() => self.reg[dst] = (self.reg[dst] as i64).wrapping_neg() as u64,
            ebpf::ST_4B_REG  if self.executable.get_sbpf_version().move_memory_instruction_classes() => {
                let vm_addr = (self.reg[dst] as i64).wrapping_add(insn.off as i64) as u64;
                translate_memory_access!(self, store, self.reg[src], vm_addr, u32);
            },
            ebpf::MOD64_IMM  if !self.executable.get_sbpf_version().enable_pqr() => self.reg[dst] %= insn.imm as u64,
            ebpf::ST_8B_IMM  if self.executable.get_sbpf_version().move_memory_instruction_classes() => {
                let vm_addr = (self.reg[dst] as i64).wrapping_add(insn.off as i64) as u64;
                translate_memory_access!(self, store, insn.imm, vm_addr, u64);
            },
            ebpf::MOD64_REG  if !self.executable.get_sbpf_version().enable_pqr() => {
                throw_error!(DivideByZero; self, self.reg[src], u64);
                                self.reg[dst] %= self.reg[src];
            },
            ebpf::ST_8B_REG  if self.executable.get_sbpf_version().move_memory_instruction_classes() => {
                let vm_addr = (self.reg[dst] as i64).wrapping_add(insn.off as i64) as u64;
                translate_memory_access!(self, store, self.reg[src], vm_addr, u64);
            },
            ebpf::XOR64_IMM  => self.reg[dst] ^= insn.imm as u64,
            ebpf::XOR64_REG  => self.reg[dst] ^= self.reg[src],
            ebpf::MOV64_IMM  => self.reg[dst] =  insn.imm as u64,
            ebpf::MOV64_REG  => self.reg[dst] =  self.reg[src],
            ebpf::ARSH64_IMM => self.reg[dst] = (self.reg[dst] as i64).wrapping_shr(insn.imm as u32)      as u64,
            ebpf::ARSH64_REG => self.reg[dst] = (self.reg[dst] as i64).wrapping_shr(self.reg[src] as u32) as u64,
            ebpf::HOR64_IMM if self.executable.get_sbpf_version().disable_lddw() => {
                self.reg[dst] |= (insn.imm as u64).wrapping_shl(32);
            }

            // BPF_PQR class
            ebpf::LMUL32_IMM if self.executable.get_sbpf_version().enable_pqr() => self.reg[dst] = (self.reg[dst] as u32).wrapping_mul(insn.imm as u32) as u64,
            ebpf::LMUL32_REG if self.executable.get_sbpf_version().enable_pqr() => self.reg[dst] = (self.reg[dst] as u32).wrapping_mul(self.reg[src] as u32) as u64,
            ebpf::LMUL64_IMM if self.executable.get_sbpf_version().enable_pqr() => self.reg[dst] = self.reg[dst].wrapping_mul(insn.imm as u64),
            ebpf::LMUL64_REG if self.executable.get_sbpf_version().enable_pqr() => self.reg[dst] = self.reg[dst].wrapping_mul(self.reg[src]),
            ebpf::UHMUL64_IMM if self.executable.get_sbpf_version().enable_pqr() => self.reg[dst] = (self.reg[dst] as u128).wrapping_mul(insn.imm as u32 as u128).wrapping_shr(64) as u64,
            ebpf::UHMUL64_REG if self.executable.get_sbpf_version().enable_pqr() => self.reg[dst] = (self.reg[dst] as u128).wrapping_mul(self.reg[src] as u128).wrapping_shr(64) as u64,
            ebpf::SHMUL64_IMM if self.executable.get_sbpf_version().enable_pqr() => self.reg[dst] = (self.reg[dst] as i64 as i128).wrapping_mul(insn.imm as i128).wrapping_shr(64) as u64,
            ebpf::SHMUL64_REG if self.executable.get_sbpf_version().enable_pqr() => self.reg[dst] = (self.reg[dst] as i64 as i128).wrapping_mul(self.reg[src] as i64 as i128).wrapping_shr(64) as u64,
            ebpf::UDIV32_IMM if self.executable.get_sbpf_version().enable_pqr() => {
                                self.reg[dst] = (self.reg[dst] as u32 / insn.imm as u32)      as u64;
            }
            ebpf::UDIV32_REG if self.executable.get_sbpf_version().enable_pqr() => {
                throw_error!(DivideByZero; self, self.reg[src], u32);
                                self.reg[dst] = (self.reg[dst] as u32 / self.reg[src] as u32) as u64;
            },
            ebpf::UDIV64_IMM if self.executable.get_sbpf_version().enable_pqr() => {
                                self.reg[dst] /= insn.imm as u32 as u64;
            }
            ebpf::UDIV64_REG if self.executable.get_sbpf_version().enable_pqr() => {
                throw_error!(DivideByZero; self, self.reg[src], u64);
                                self.reg[dst] /= self.reg[src];
            },
            ebpf::UREM32_IMM if self.executable.get_sbpf_version().enable_pqr() => {
                                self.reg[dst] = (self.reg[dst] as u32 % insn.imm as u32)      as u64;
            }
            ebpf::UREM32_REG if self.executable.get_sbpf_version().enable_pqr() => {
                throw_error!(DivideByZero; self, self.reg[src], u32);
                                self.reg[dst] = (self.reg[dst] as u32 % self.reg[src] as u32) as u64;
            },
            ebpf::UREM64_IMM if self.executable.get_sbpf_version().enable_pqr() => {
                                self.reg[dst] %= insn.imm as u32 as u64;
            }
            ebpf::UREM64_REG if self.executable.get_sbpf_version().enable_pqr() => {
                throw_error!(DivideByZero; self, self.reg[src], u64);
                                self.reg[dst] %= self.reg[src];
            },
            ebpf::SDIV32_IMM if self.executable.get_sbpf_version().enable_pqr() => {
                throw_error!(DivideOverflow; self, insn.imm, self.reg[dst], i32);
                                self.reg[dst] = (self.reg[dst] as i32 / insn.imm as i32)      as u32 as u64;
            }
            ebpf::SDIV32_REG if self.executable.get_sbpf_version().enable_pqr() => {
                throw_error!(DivideByZero; self, self.reg[src], i32);
                throw_error!(DivideOverflow; self, self.reg[src], self.reg[dst], i32);
                                self.reg[dst] = (self.reg[dst] as i32 / self.reg[src] as i32) as u32 as u64;
            },
            ebpf::SDIV64_IMM if self.executable.get_sbpf_version().enable_pqr() => {
                throw_error!(DivideOverflow; self, insn.imm, self.reg[dst], i64);
                                self.reg[dst] = (self.reg[dst] as i64 / insn.imm)             as u64;
            }
            ebpf::SDIV64_REG if self.executable.get_sbpf_version().enable_pqr() => {
                throw_error!(DivideByZero; self, self.reg[src], i64);
                throw_error!(DivideOverflow; self, self.reg[src], self.reg[dst], i64);
                                self.reg[dst] = (self.reg[dst] as i64 / self.reg[src] as i64) as u64;
            },
            ebpf::SREM32_IMM if self.executable.get_sbpf_version().enable_pqr() => {
                throw_error!(DivideOverflow; self, insn.imm, self.reg[dst], i32);
                                self.reg[dst] = (self.reg[dst] as i32 % insn.imm as i32)      as u32 as u64;
            }
            ebpf::SREM32_REG if self.executable.get_sbpf_version().enable_pqr() => {
                throw_error!(DivideByZero; self, self.reg[src], i32);
                throw_error!(DivideOverflow; self, self.reg[src], self.reg[dst], i32);
                                self.reg[dst] = (self.reg[dst] as i32 % self.reg[src] as i32) as u32 as u64;
            },
            ebpf::SREM64_IMM if self.executable.get_sbpf_version().enable_pqr() => {
                throw_error!(DivideOverflow; self, insn.imm, self.reg[dst], i64);
                                self.reg[dst] = (self.reg[dst] as i64 % insn.imm)             as u64;
            }
            ebpf::SREM64_REG if self.executable.get_sbpf_version().enable_pqr() => {
                throw_error!(DivideByZero; self, self.reg[src], i64);
                throw_error!(DivideOverflow; self, self.reg[src], self.reg[dst], i64);
                                self.reg[dst] = (self.reg[dst] as i64 % self.reg[src] as i64) as u64;
            },

            // BPF_JMP32 class
            ebpf::JEQ32_IMM  if self.executable.get_sbpf_version().enable_jmp32() => if (self.reg[dst] as u32) == insn.imm as u32           { next_pc = (next_pc as i64 + insn.off as i64) as u64; },
            ebpf::JEQ32_REG  if self.executable.get_sbpf_version().enable_jmp32() => if (self.reg[dst] as u32) == self.reg[src] as u32      { next_pc = (next_pc as i64 + insn.off as i64) as u64; },
            ebpf::JGT32_IMM  if self.executable.get_sbpf_version().enable_jmp32() => if (self.reg[dst] as u32) >  insn.imm as u32           { next_pc = (next_pc as i64 + insn.off as i64) as u64; },
            ebpf::JGT32_REG  if self.executable.get_sbpf_version().enable_jmp32() => if (self.reg[dst] as u32) >  self.reg[src] as u32      { next_pc = (next_pc as i64 + insn.off as i64) as u64; },
            ebpf::JGE32_IMM  if self.executable.get_sbpf_version().enable_jmp32() => if (self.reg[dst] as u32) >= insn.imm as u32           { next_pc = (next_pc as i64 + insn.off as i64) as u64; },
            ebpf::JGE32_REG  if self.executable.get_sbpf_version().enable_jmp32() => if (self.reg[dst] as u32) >= self.reg[src] as u32      { next_pc = (next_pc as i64 + insn.off as i64) as u64; },
            ebpf::JLT32_IMM  if self.executable.get_sbpf_version().enable_jmp32() => if (self.reg[dst] as u32) <  insn.imm as u32           { next_pc = (next_pc as i64 + insn.off as i64) as u64; },
            ebpf::JLT32_REG  if self.executable.get_sbpf_version().enable_jmp32() => if (self.reg[dst] as u32) <  self.reg[src] as u32      { next_pc = (next_pc as i64 + insn.off as i64) as u64; },
            ebpf::JLE32_IMM  if self.executable.get_sbpf_version().enable_jmp32() => if (self.reg[dst] as u32) <= insn.imm as u32           { next_pc = (next_pc as i64 + insn.off as i64) as u64; },
            ebpf::JLE32_REG  if self.executable.get_sbpf_version().enable_jmp32() => if (self.reg[dst] as u32) <= self.reg[src] as u32      { next_pc = (next_pc as i64 + insn.off as i64) as u64; },
            ebpf::JSET32_IMM if self.executable.get_sbpf_version().enable_jmp32() => if (self.reg[dst] as u32) &  insn.imm as u32 != 0      { next_pc = (next_pc as i64 + insn.off as i64) as u64; },
            ebpf::JSET32_REG if self.executable.get_sbpf_version().enable_jmp32() => if (self.reg[dst] as u32) &  self.reg[src] as u32 != 0 { next_pc = (next_pc as i64 + insn.off as i64) as u64; },
            ebpf::JNE32_IMM  if self.executable.get_sbpf_version().enable_jmp32() => if (self.reg[dst] as u32) != insn.imm as u32           { next_pc = (next_pc as i64 + insn.off as i64) as u64; },
            ebpf::JNE32_REG  if self.executable.get_sbpf_version().enable_jmp32() => if (self.reg[dst] as u32) != self.reg[src] as u32      { next_pc = (next_pc as i64 + insn.off as i64) as u64; },
            ebpf::JSGT32_IMM if self.executable.get_sbpf_version().enable_jmp32() => if (self.reg[dst] as i32) >  insn.imm as i32           { next_pc = (next_pc as i64 + insn.off as i64) as u64; },
            ebpf::JSGT32_REG if self.executable.get_sbpf_version().enable_jmp32() => if (self.reg[dst] as i32) >  self.reg[src] as i32      { next_pc = (next_pc as i64 + insn.off as i64) as u64; },
            ebpf::JSGE32_IMM if self.executable.get_sbpf_version().enable_jmp32() => if (self.reg[dst] as i32) >= insn.imm as i32           { next_pc = (next_pc as i64 + insn.off as i64) as u64; },
            ebpf::JSGE32_REG if self.executable.get_sbpf_version().enable_jmp32() => if (self.reg[dst] as i32) >= self.reg[src] as i32      { next_pc = (next_pc as i64 + insn.off as i64) as u64; },
            ebpf::JSLT32_IMM if self.executable.get_sbpf_version().enable_jmp32() => if (self.reg[dst] as i32) <  insn.imm as i32           { next_pc = (next_pc as i64 + insn.off as i64) as u64; },
            ebpf::JSLT32_REG if self.executable.get_sbpf_version().enable_jmp32() => if (self.reg[dst] as i32) <  self.reg[src] as i32      { next_pc = (next_pc as i64 + insn.off as i64) as u64; },
            ebpf::JSLE32_IMM if self.executable.get_sbpf_version().enable_jmp32() => if (self.reg[dst] as i32) <= insn.imm as i32           { next_pc = (next_pc as i64 + insn.off as i64) as u64; },
            ebpf::JSLE32_REG if self.executable.get_sbpf_version().enable_jmp32() => if (self.reg[dst] as i32) <= self.reg[src] as i32      { next_pc = (next_pc as i64 + insn.off as i64) as u64; },

            // BPF_JMP64 class
            ebpf::JA         =>                                                   { next_pc = (next_pc as i64 + insn.off as i64) as u64; },
            ebpf::JEQ64_IMM    => if  self.reg[dst] == insn.imm as u64              { next_pc = (next_pc as i64 + insn.off as i64) as u64; },
            ebpf::JEQ64_REG    => if  self.reg[dst] == self.reg[src]                { next_pc = (next_pc as i64 + insn.off as i64) as u64; },
            ebpf::JGT64_IMM    => if  self.reg[dst] >  insn.imm as u64              { next_pc = (next_pc as i64 + insn.off as i64) as u64; },
            ebpf::JGT64_REG    => if  self.reg[dst] >  self.reg[src]                { next_pc = (next_pc as i64 + insn.off as i64) as u64; },
            ebpf::JGE64_IMM    => if  self.reg[dst] >= insn.imm as u64              { next_pc = (next_pc as i64 + insn.off as i64) as u64; },
            ebpf::JGE64_REG    => if  self.reg[dst] >= self.reg[src]                { next_pc = (next_pc as i64 + insn.off as i64) as u64; },
            ebpf::JLT64_IMM    => if  self.reg[dst] <  insn.imm as u64              { next_pc = (next_pc as i64 + insn.off as i64) as u64; },
            ebpf::JLT64_REG    => if  self.reg[dst] <  self.reg[src]                { next_pc = (next_pc as i64 + insn.off as i64) as u64; },
            ebpf::JLE64_IMM    => if  self.reg[dst] <= insn.imm as u64              { next_pc = (next_pc as i64 + insn.off as i64) as u64; },
            ebpf::JLE64_REG    => if  self.reg[dst] <= self.reg[src]                { next_pc = (next_pc as i64 + insn.off as i64) as u64; },
            ebpf::JSET64_IMM   => if  self.reg[dst] &  insn.imm as u64 != 0         { next_pc = (next_pc as i64 + insn.off as i64) as u64; },
            ebpf::JSET64_REG   => if  self.reg[dst] &  self.reg[src] != 0           { next_pc = (next_pc as i64 + insn.off as i64) as u64; },
            ebpf::JNE64_IMM    => if  self.reg[dst] != insn.imm as u64              { next_pc = (next_pc as i64 + insn.off as i64) as u64; },
            ebpf::JNE64_REG    => if  self.reg[dst] != self.reg[src]                { next_pc = (next_pc as i64 + insn.off as i64) as u64; },
            ebpf::JSGT64_IMM   => if (self.reg[dst] as i64) >  insn.imm             { next_pc = (next_pc as i64 + insn.off as i64) as u64; },
            ebpf::JSGT64_REG   => if (self.reg[dst] as i64) >  self.reg[src] as i64 { next_pc = (next_pc as i64 + insn.off as i64) as u64; },
            ebpf::JSGE64_IMM   => if (self.reg[dst] as i64) >= insn.imm             { next_pc = (next_pc as i64 + insn.off as i64) as u64; },
            ebpf::JSGE64_REG   => if (self.reg[dst] as i64) >= self.reg[src] as i64 { next_pc = (next_pc as i64 + insn.off as i64) as u64; },
            ebpf::JSLT64_IMM   => if (self.reg[dst] as i64) <  insn.imm             { next_pc = (next_pc as i64 + insn.off as i64) as u64; },
            ebpf::JSLT64_REG   => if (self.reg[dst] as i64) <  self.reg[src] as i64 { next_pc = (next_pc as i64 + insn.off as i64) as u64; },
            ebpf::JSLE64_IMM   => if (self.reg[dst] as i64) <= insn.imm             { next_pc = (next_pc as i64 + insn.off as i64) as u64; },
            ebpf::JSLE64_REG   => if (self.reg[dst] as i64) <= self.reg[src] as i64 { next_pc = (next_pc as i64 + insn.off as i64) as u64; },

            ebpf::CALL_REG   => {
                let target_pc = if self.executable.get_sbpf_version().callx_uses_src_reg() {
                    self.reg[src]
                } else if self.executable.get_sbpf_version().callx_uses_dst_reg() {
                    self.reg[dst]
                } else {
                    self.reg[insn.imm as usize]
                };
                let _call_depth_before = self.vm.call_depth;
                let _call_fn_pc = self.current_function_pc();
                if !self.push_frame(config) {
                    return false;
                }
                check_pc!(self, next_pc, target_pc.wrapping_sub(self.program_vm_addr) / ebpf::INSN_SIZE as u64);




                self.function_pc_stack.push(next_pc);
                let passes_program_filter = self
                    .vm
                    .trace_config
                    .trace_filter_program_id
                    .map_or(true, |filter_pid| filter_pid == self.vm.trace_config.current_program_id);
                if passes_program_filter && self.vm.trace_config.trace_calls {
                    let entry = crate::vm::CallTraceEntry {
                        pc: self.reg[11],
                        program_id: self.vm.trace_config.current_program_id,
                        target_pc: next_pc,
                        function_pc: _call_fn_pc,
                        call_depth: _call_depth_before,
                        is_return: false,
                        args: [self.reg[0], self.reg[1], self.reg[2], self.reg[3], self.reg[4], self.reg[5]],
                    };
                    if self.vm.trace_config.trace_stream {
                        self.vm.call_trace.push(entry.clone());
                        crate::vm::TraceEvent::Call(entry).stream_print();
                    } else {
                        self.vm.call_trace.push(entry);
                    }
                }
            },

            ebpf::CALL_IMM => {
                let mut resolved = false;
                let _call_depth_before = self.vm.call_depth;
                    let _call_fn_pc = self.current_function_pc();
                    let passes_program_filter = self
                        .vm
                        .trace_config
                        .trace_filter_program_id
                        .map_or(true, |filter_pid| filter_pid == self.vm.trace_config.current_program_id);
                // External syscall
                if !self.executable.get_sbpf_version().static_syscalls() || insn.src == 0 {

                    if let Some((fn_name_bytes, (callback, _))) = self.executable.get_loader().get_function_registry().lookup_by_key(insn.imm as u32) {
                        // capture args BEFORE dispatch — reg[1..5] may change after
                                  let _should_trace = passes_program_filter
                                      && self.vm.trace_config.trace_syscalls
                                      && self.vm.trace_config.target_program_addr
                                          .map_or(true, |t| t == self.program_vm_addr)
                                      && _pc_range_ok
                                      && _func_filter_ok;
                                  let _syscall_args = if _should_trace {
                                      Some((
                                          String::from_utf8_lossy(fn_name_bytes).into_owned(),
                                          [self.reg[1], self.reg[2], self.reg[3], self.reg[4], self.reg[5]],
                                      ))
                                  } else {
                                      None
                                  };
                        self.reg[0] = match self.dispatch_syscall(callback) {
                            ProgramResult::Ok(value) => *value,
                            ProgramResult::Err(_err) => return false,
                        };
                        // record AFTER dispatch so result (reg[0]) is captured
                                  if let Some((name, args)) = _syscall_args {
                                      let entry = crate::vm::SyscallTraceEntry {
                                          pc: self.reg[11],
                                          program_id: self.vm.trace_config.current_program_id,
                                          name,
                                          args,
                                          result: self.reg[0],
                                          function_pc: self.current_function_pc(),
                                          call_depth: self.vm.call_depth,
                                      };
                                      if self.vm.trace_config.trace_stream {
                                          self.vm.syscall_trace.push(entry.clone());
                                          crate::vm::TraceEvent::Syscall(entry).stream_print();
                                      } else {
                                          self.vm.syscall_trace.push(entry);
                                      }
                                  }
                        resolved = true;
                    }
                }
                // Internal call
                if self.executable.get_sbpf_version().static_syscalls() {
                    let target_pc = (next_pc as i64).saturating_add(insn.imm);
                    if ebpf::is_pc_in_program(self.program, target_pc as usize) && insn.src == 1 {
                        if !self.push_frame(config) {
                            return false;
                        }
                        next_pc = target_pc as u64;
                       self.function_pc_stack.push(next_pc);
                                   if passes_program_filter && self.vm.trace_config.trace_calls {
                                       let entry = crate::vm::CallTraceEntry {
                                           pc: self.reg[11],
                                           program_id: self.vm.trace_config.current_program_id,
                                           target_pc: next_pc,
                                           function_pc: _call_fn_pc,
                                           call_depth: _call_depth_before,
                                           is_return: false,
                                           args: [
                                               self.reg[0], self.reg[1], self.reg[2],
                                               self.reg[3], self.reg[4], self.reg[5],
                                           ],
                                       };
                                       if self.vm.trace_config.trace_stream {
                                           self.vm.call_trace.push(entry.clone());
                                           crate::vm::TraceEvent::Call(entry).stream_print();
                                       } else {
                                           self.vm.call_trace.push(entry);
                                       }
                                   }
                        resolved = true;
                    }
                } else if let Some((_, target_pc)) =
                    self.executable
                    .get_function_registry()
                    .lookup_by_key(insn.imm as u32) {
                    if !self.push_frame(config) {
                        return false;
                    }
                    check_pc!(self, next_pc, target_pc as u64);
                    self.function_pc_stack.push(next_pc);
                           if passes_program_filter && self.vm.trace_config.trace_calls {
                               let entry = crate::vm::CallTraceEntry {
                                   pc: self.reg[11],
                                   program_id: self.vm.trace_config.current_program_id,
                                   target_pc: next_pc,
                                   function_pc: _call_fn_pc,
                                   call_depth: _call_depth_before,
                                   is_return: false,
                                   args: [
                                       self.reg[0], self.reg[1], self.reg[2],
                                       self.reg[3], self.reg[4], self.reg[5],
                                   ],
                               };
                               if self.vm.trace_config.trace_stream {
                                   self.vm.call_trace.push(entry.clone());
                                   crate::vm::TraceEvent::Call(entry).stream_print();
                               } else {
                                   self.vm.call_trace.push(entry);
                               }
                           }
                    resolved = true;
                }
                if !resolved {
                    throw_error!(self, EbpfError::UnsupportedInstruction);
                }
            }
            ebpf::EXIT       => {
                if self.vm.call_depth == 0 {
                    if config.enable_instruction_meter && self.vm.due_insn_count > self.vm.previous_instruction_meter {
                        throw_error!(self, EbpfError::ExceededMaxInstructions);
                    }
                    self.vm.program_result = ProgramResult::Ok(self.reg[0]);
                    return false;
                }
                // Return from BPF to BPF call
                let _ret_fn_pc = self.current_function_pc();
                let _ret_depth = self.vm.call_depth;
                let _ret_val = self.reg[0];
                self.vm.call_depth -= 1;
                  self.function_pc_stack.pop();
                let frame = &self.call_frames[self.vm.call_depth as usize];

                self.reg[ebpf::FRAME_PTR_REG] = frame.frame_pointer;
                self.reg[ebpf::FIRST_SCRATCH_REG
                    ..ebpf::FIRST_SCRATCH_REG + ebpf::SCRATCH_REGS]
                    .copy_from_slice(&frame.caller_saved_registers);
                next_pc = frame.target_pc;
                let passes_program_filter = self
                    .vm
                    .trace_config
                    .trace_filter_program_id
                    .map_or(true, |filter_pid| filter_pid == self.vm.trace_config.current_program_id);
                if passes_program_filter && self.vm.trace_config.trace_calls {
                    let entry = crate::vm::CallTraceEntry {
                        pc: self.reg[11],
                        program_id: self.vm.trace_config.current_program_id,
                        target_pc: next_pc,
                        function_pc: _ret_fn_pc,
                        call_depth: _ret_depth,
                        is_return: true,
                        args: [_ret_val, 0, 0, 0, 0, 0],
                    };
                    if self.vm.trace_config.trace_stream {
                        self.vm.call_trace.push(entry.clone());
                        crate::vm::TraceEvent::Call(entry).stream_print();
                    } else {
                        self.vm.call_trace.push(entry);
                    }
                }
            }
            _ => throw_error!(self, EbpfError::UnsupportedInstruction),
        }
        // ALU value match trace: print when dst register after ALU op matches target value
        if let Some(match_val) = self.alu_value_match {
            let new_dst = self.reg[dst];
            if new_dst == match_val && new_dst != _insn_dst_before {
                if let Some((category, opcode_name)) = Self::classify_opcode(insn.opc) {
                    if category == "alu" {
                        eprintln!(
                            "[SBPF_ALU_MATCH] PC={} (0x{:x}) {} r{}={} <- r{}={} imm={} | dst_before={}",
                            self.reg[11], self.reg[11] * 8,
                            opcode_name, dst, new_dst, src, _insn_src_val, insn.imm,
                            _insn_dst_before
                        );
                        for i in 0..10u8 {
                            eprintln!("[SBPF_ALU_MATCH]   r{} = 0x{:016x} ({})", i, self.reg[i as usize], self.reg[i as usize] as i64);
                        }
                    }
                }
            }
        }

        let passes_program_filter = self
            .vm
            .trace_config
            .trace_filter_program_id
            .map_or(true, |filter_pid| filter_pid == self.vm.trace_config.current_program_id);

        if passes_program_filter && _insn_trace_active {
            if let Some((category, opcode_name)) = Self::classify_opcode(insn.opc) {
                let cats = &self.vm.trace_config.insn_categories;
                let wanted = match category {
                    "alu" => cats.alu,
                    "jump" => cats.jump,
                    "call" => cats.call,
                    _ => false,
                };
                if wanted {
                    let (branch_taken, branch_target) = if category == "jump" {
                        let taken = next_pc != _insn_old_next_pc;
                        (Some(taken), if taken { Some(next_pc) } else { None })
                    } else {
                        (None, None)
                    };
                    let entry = crate::vm::InsnTraceEntry {
                        pc: self.reg[11],
                        program_id: self.vm.trace_config.current_program_id,
                        opcode: insn.opc,
                        opcode_name,
                        category,
                        dst: insn.dst,
                        src: insn.src,
                        imm: insn.imm,
                        off: insn.off,
                        dst_val_before: _insn_dst_before,
                        dst_val_after: self.reg[dst],
                        src_val: _insn_src_val,
                        branch_taken,
                        branch_target,
                        function_pc: self.current_function_pc(),
                        call_depth: self.vm.call_depth,
                    };
                    if self.vm.trace_config.trace_stream {
                        self.vm.insn_trace.push(entry.clone());
                        crate::vm::TraceEvent::Instruction(entry).stream_print();
                    } else {
                        self.vm.insn_trace.push(entry);
                    }
                }
            }}
        self.reg[11] = next_pc;
        true
    }
    fn dump_breakpoint_hit(&mut self) {
        let pc = self.reg[11];
        let byte_off = pc * ebpf::INSN_SIZE as u64;
        eprintln!(
            "[SBPF_BP] === HIT PC={} (0x{:x}) insn#{} ===",
            pc,
            byte_off,
            self.trace_pos - 1
        );
        for i in 0..12u8 {
            let name = if i == 10 {
                "sp".to_string()
            } else if i == 11 {
                "pc".to_string()
            } else {
                format!("r{}", i)
            };
            eprintln!(
                "[SBPF_BP]   {:>3} = 0x{:016x} ({})",
                name, self.reg[i as usize], self.reg[i as usize]
            );
        }
        for &(label, reg_idx) in &[("r1", 1usize), ("r2", 2), ("r3", 3)] {
            let addr = self.reg[reg_idx];
            if addr >= 0x100000000 {
                let mut buf = [0u8; 80];
                let mut read_len = 0usize;
                for i in 0..80 {
                    match self.vm.memory().load::<u8>(addr + i as u64) {
                        ProgramResult::Ok(v) => {
                            buf[i] = v as u8;
                            read_len = i + 1;
                        }
                        _ => break,
                    }
                }
                if read_len > 0 {
                    eprintln!(
                        "[SBPF_BP]   mem[{}=0x{:x}] first {} bytes: {:02x?}",
                        label,
                        addr,
                        read_len.min(64),
                        &buf[..read_len.min(64)]
                    );
                }
            }
        }
        eprintln!("[SBPF_BP] === END ===");
    }

    //inspect crash reason
    pub(crate) fn dump_trace_on_error(&mut self) {
        if !self.trace_enabled {
            return;
        }
        let is_err = matches!(&self.vm.program_result, ProgramResult::Err(_));
        let force_dump = std::env::var("SBPF_TRACE_DUMP").is_ok();
        if !is_err && !force_dump {
            return;
        }
        let passes_filter = self
            .trace_filter_len
            .map_or(true, |filter| filter == self.program.len());
        if !passes_filter {
            return;
        }

        let count = self.trace_pos.min(TRACE_RING_SIZE);
        let start = if self.trace_pos > TRACE_RING_SIZE {
            self.trace_pos % TRACE_RING_SIZE
        } else {
            0
        };

        if is_err {
            eprintln!(
                "[SBPF_TRACE] === CRASH after {} instructions ===",
                self.trace_pos
            );
            eprintln!("[SBPF_TRACE] error: {:?}", self.vm.program_result);
        } else {
            eprintln!(
                "[SBPF_TRACE] === DONE after {} instructions ===",
                self.trace_pos
            );
        }
        eprintln!(
            "[SBPF_TRACE] program_vm_addr: 0x{:x} len={}",
            self.program_vm_addr,
            self.program.len()
        );

        if count > 0 {
            let last_idx = if self.trace_pos > TRACE_RING_SIZE {
                (self.trace_pos - 1) % TRACE_RING_SIZE
            } else {
                self.trace_pos - 1
            };
            let last = &self.trace_ring[last_idx];
            // sol_invoke_signed_c: opc=0x85 (CALL_IMM), r1=instruction_addr
            // SolInstruction_C layout: program_id_addr(8), accounts_addr(8), accounts_len(8), data_addr(8), data_len(8) = 40 bytes
            if last.opc == 0x85 {
                let cpi_addr = last.regs[1];
                eprintln!(
                    "[SBPF_TRACE] last insn is CALL_IMM(0x{:x}) r1=0x{:x} r2=0x{:x} r3=0x{:x} r4=0x{:x} r5=0x{:x}",
                    last.imm as u32, cpi_addr, last.regs[2], last.regs[3], last.regs[4], last.regs[5]
                );
                let mut raw80 = [0u8; 80];
                for (off, b) in raw80.iter_mut().enumerate() {
                    if let ProgramResult::Ok(v) = self.vm.memory().load::<u8>(cpi_addr + off as u64)
                    {
                        *b = v as u8;
                    }
                }
                eprintln!("[SBPF_TRACE]   raw 80B at r1: {:02x?}", &raw80[..]);
                eprintln!("[SBPF_TRACE]   StableInstruction decode:");
                eprintln!("[SBPF_TRACE]     accounts.ptr=0x{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x} len={} cap={}",
                    raw80[7],raw80[6],raw80[5],raw80[4],raw80[3],raw80[2],raw80[1],raw80[0],
                    u64::from_le_bytes([raw80[8],raw80[9],raw80[10],raw80[11],raw80[12],raw80[13],raw80[14],raw80[15]]),
                    u64::from_le_bytes([raw80[16],raw80[17],raw80[18],raw80[19],raw80[20],raw80[21],raw80[22],raw80[23]]));
                eprintln!("[SBPF_TRACE]     data.ptr=0x{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x} len={} cap={}",
                    raw80[31],raw80[30],raw80[29],raw80[28],raw80[27],raw80[26],raw80[25],raw80[24],
                    u64::from_le_bytes([raw80[32],raw80[33],raw80[34],raw80[35],raw80[36],raw80[37],raw80[38],raw80[39]]),
                    u64::from_le_bytes([raw80[40],raw80[41],raw80[42],raw80[43],raw80[44],raw80[45],raw80[46],raw80[47]]));
                eprintln!(
                    "[SBPF_TRACE]     program_id (offset 48): {:02x?}",
                    &raw80[48..80]
                );

                let mut buf = [0u8; 40];
                let mut ok = true;
                for (off, b) in buf.iter_mut().enumerate() {
                    let vm_a = cpi_addr + off as u64;
                    match self.vm.memory().load::<u8>(vm_a) {
                        ProgramResult::Ok(v) => *b = v as u8,
                        _ => {
                            ok = false;
                            break;
                        }
                    }
                }
                if ok {
                    let rd = |off: usize| -> u64 {
                        let mut a = [0u8; 8];
                        a.copy_from_slice(&buf[off..off + 8]);
                        u64::from_le_bytes(a)
                    };
                    let pid_ptr = rd(0);
                    let accts_ptr = rd(8);
                    let accts_len = rd(16);
                    let data_ptr = rd(24);
                    let data_len = rd(32);
                    eprintln!("[SBPF_TRACE]   program_id_ptr=0x{:x} accounts_ptr=0x{:x} accounts_len={} data_ptr=0x{:x} data_len={}",
                        pid_ptr, accts_ptr, accts_len, data_ptr, data_len);

                    let mut pid = [0u8; 32];
                    let mut pid_ok = true;
                    for (off, b) in pid.iter_mut().enumerate() {
                        match self.vm.memory().load::<u8>(pid_ptr + off as u64) {
                            ProgramResult::Ok(v) => *b = v as u8,
                            _ => {
                                pid_ok = false;
                                break;
                            }
                        }
                    }
                    if pid_ok {
                        eprintln!("[SBPF_TRACE]   CPI target program_id (hex): {:02x?}", &pid);
                    }

                    let mut data_head = [0u8; 32];
                    let dh_len = (data_len as usize).min(32);
                    let mut dh_ok = true;
                    for i in 0..dh_len {
                        match self.vm.memory().load::<u8>(data_ptr + i as u64) {
                            ProgramResult::Ok(v) => data_head[i] = v as u8,
                            _ => {
                                dh_ok = false;
                                break;
                            }
                        }
                    }
                    if dh_ok {
                        eprintln!(
                            "[SBPF_TRACE]   CPI data[..{}]: {:02x?}",
                            dh_len,
                            &data_head[..dh_len]
                        );
                    }
                }
            }
        }

        eprintln!(
            "[SBPF_TRACE] last {} instructions (of {} total) prog=0x{:x}:",
            count, self.trace_pos, self.program_vm_addr
        );

        for i in 0..count {
            let idx = (start + i) % TRACE_RING_SIZE;
            let e = &self.trace_ring[idx];
            let byte_offset = e.pc * (ebpf::INSN_SIZE as u64);
            eprintln!(
                "[SBPF_TRACE] prog=0x{:x} {:>4} PC={:<6} off=0x{:<8x} opc=0x{:02x} dst=r{} src=r{} off={:<6} imm=0x{:x}  | r0=0x{:x} r1=0x{:x} r2=0x{:x} r3=0x{:x} r4=0x{:x} r5=0x{:x} r10=0x{:x}",
                self.program_vm_addr,
                i, e.pc, byte_offset, e.opc, e.dst, e.src, e.off, e.imm,
                e.regs[0], e.regs[1], e.regs[2], e.regs[3], e.regs[4], e.regs[5], e.regs[10],
            );
        }
        eprintln!("[SBPF_TRACE] === END prog=0x{:x} ===", self.program_vm_addr);
    }

    //captures what CPIs are being made and reports syscall failures with context
    fn dispatch_syscall(&mut self, function: BuiltinFunction<C>) -> &ProgramResult {
        self.vm.due_insn_count = self.vm.previous_instruction_meter - self.vm.due_insn_count;
        self.vm.registers[0..6].copy_from_slice(&self.reg[0..6]);
        let passes_program_filter = self
            .vm
            .trace_config
            .trace_filter_program_id
            .map_or(true, |filter_pid| {
                filter_pid == self.vm.trace_config.current_program_id
            });
        if passes_program_filter && self.vm.trace_config.trace_cpi_decode {
            let ix_ptr = self.reg[1];
            let mut entry = crate::vm::CpiDecodeEntry {
                pc: self.reg[11],
                program_id: self.vm.trace_config.current_program_id,
                ..Default::default()
            };
            if let ProgramResult::Ok(pid_ptr) = self.vm.memory().load::<u64>(ix_ptr) {
                let mut id_ok = true;
                for i in 0..32u64 {
                    if self.vm.memory().load::<u8>(pid_ptr + i).is_err() {
                        id_ok = false;
                        break;
                    }
                }
                if id_ok {
                    if let ProgramResult::Ok(accs_len) = self.vm.memory().load::<u64>(ix_ptr + 16) {
                        entry.accounts_len = accs_len;
                    }
                    if let ProgramResult::Ok(data_len) = self.vm.memory().load::<u64>(ix_ptr + 32) {
                        entry.data_len = data_len;
                        if let ProgramResult::Ok(data_ptr) =
                            self.vm.memory().load::<u64>(ix_ptr + 24)
                        {
                            let preview_len = data_len.min(32);
                            for i in 0..preview_len {
                                if let ProgramResult::Ok(b) =
                                    self.vm.memory().load::<u8>(data_ptr + i)
                                {
                                    entry.data_preview.push(b as u8);
                                } else {
                                    break;
                                }
                            }
                        }
                    }
                    if self.vm.trace_config.trace_stream {
                        self.vm.cpi_decode_trace.push(entry.clone());
                        crate::vm::TraceEvent::CpiDecode(entry).stream_print();
                    } else {
                        self.vm.cpi_decode_trace.push(entry);
                    }
                }
            }
        }
        self.vm.invoke_function(function);
        self.vm.due_insn_count = 0;
        if self.trace_enabled {
            if let ProgramResult::Err(ref e) = self.vm.program_result {
                eprintln!(
                    "[SBPF_TRACE] syscall returned error at PC={}: {:?}",
                    self.reg[11], e
                );
            }
        }
        &self.vm.program_result
    }
}


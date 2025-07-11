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
    vm::{Config, ContextObject, EbpfVm},
};

/// Virtual memory operation helper.
macro_rules! translate_memory_access {
    (_impl, $self:ident, $op:ident, $vm_addr:ident, $T:ty, $($rest:expr),*) => {
        match $self.vm.memory_mapping.$op::<$T>(
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
    ($self:ident, load, $vm_addr:ident, $T:ty) => {
        translate_memory_access!(_impl, $self, load, $vm_addr, $T,)
    };

    // MemoryMapping::store()
    ($self:ident, store, $value:expr, $vm_addr:ident, $T:ty) => {
        translate_memory_access!(_impl, $self, store, $vm_addr, $T, ($value) as $T);
    };
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
        if ($target_pc as usize)
            .checked_mul(ebpf::INSN_SIZE)
            .and_then(|offset| {
                $self
                    .program
                    .get(offset..offset.saturating_add(ebpf::INSN_SIZE))
            })
            .is_some()
        {
            $next_pc = $target_pc;
        } else {
            throw_error!($self, EbpfError::CallOutsideTextSegment);
        }
    };
}

/// State of the interpreter during a debugging session
#[cfg(feature = "debugger")]
pub enum DebugState {
    /// Single step the interpreter
    Step,
    /// Continue execution till the end or till a breakpoint is hit
    Continue,
}

/// State of an interpreter
pub struct Interpreter<'a, 'b, C: ContextObject> {
    pub(crate) vm: &'a mut EbpfVm<'b, C>,
    pub(crate) executable: &'a Executable<C>,
    pub(crate) program: &'a [u8],
    pub(crate) program_vm_addr: u64,

    /// General purpose registers and pc
    pub reg: [u64; 12],

    #[cfg(feature = "debugger")]
    pub(crate) debug_state: DebugState,
    #[cfg(feature = "debugger")]
    pub(crate) breakpoints: Vec<u64>,
}

impl<'a, 'b, C: ContextObject> Interpreter<'a, 'b, C> {
    /// Creates a new interpreter state
    pub fn new(
        vm: &'a mut EbpfVm<'b, C>,
        executable: &'a Executable<C>,
        registers: [u64; 12],
    ) -> Self {
        let (program_vm_addr, program) = executable.get_text_bytes();
        Self {
            vm,
            executable,
            program,
            program_vm_addr,
            reg: registers,
            #[cfg(feature = "debugger")]
            debug_state: DebugState::Continue,
            #[cfg(feature = "debugger")]
            breakpoints: Vec::new(),
        }
    }

    /// Translate between the virtual machines' pc value and the pc value used by the debugger
    #[cfg(feature = "debugger")]
    pub fn get_dbg_pc(&self) -> u64 {
        (self.reg[11] * ebpf::INSN_SIZE as u64) + self.executable.get_text_section_offset()
    }

    fn push_frame(&mut self, config: &Config) -> bool {
        let frame = &mut self.vm.call_frames[self.vm.call_depth as usize];
        frame.caller_saved_registers.copy_from_slice(
            &self.reg[ebpf::FIRST_SCRATCH_REG..ebpf::FIRST_SCRATCH_REG + ebpf::SCRATCH_REGS],
        );
        frame.frame_pointer = self.reg[ebpf::FRAME_PTR_REG];
        frame.target_pc = self.reg[11] + 1;

        self.vm.call_depth += 1;
        if self.vm.call_depth as usize == config.max_call_depth {
            throw_error!(self, EbpfError::CallDepthExceeded);
        }

        if !self.executable.get_sbpf_version().dynamic_stack_frames() {
            // With fixed frames we start the new frame at the next fixed offset
            let stack_frame_size =
                config.stack_frame_size * if config.enable_stack_frame_gaps { 2 } else { 1 };
            self.reg[ebpf::FRAME_PTR_REG] += stack_frame_size as u64;
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

        if config.enable_instruction_tracing {
            self.vm.context_object_pointer.trace(self.reg);
        }

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
            ebpf::MUL32_IMM  if !self.executable.get_sbpf_version().enable_pqr() => self.reg[dst] = (self.reg[dst] as i32).wrapping_mul(insn.imm as i32)      as u64,
            ebpf::MUL32_REG  if !self.executable.get_sbpf_version().enable_pqr() => self.reg[dst] = (self.reg[dst] as i32).wrapping_mul(self.reg[src] as i32) as u64,
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

            // BPF_JMP class
            ebpf::JA         =>                                                   { next_pc = (next_pc as i64 + insn.off as i64) as u64; },
            ebpf::JEQ_IMM    => if  self.reg[dst] == insn.imm as u64              { next_pc = (next_pc as i64 + insn.off as i64) as u64; },
            ebpf::JEQ_REG    => if  self.reg[dst] == self.reg[src]                { next_pc = (next_pc as i64 + insn.off as i64) as u64; },
            ebpf::JGT_IMM    => if  self.reg[dst] >  insn.imm as u64              { next_pc = (next_pc as i64 + insn.off as i64) as u64; },
            ebpf::JGT_REG    => if  self.reg[dst] >  self.reg[src]                { next_pc = (next_pc as i64 + insn.off as i64) as u64; },
            ebpf::JGE_IMM    => if  self.reg[dst] >= insn.imm as u64              { next_pc = (next_pc as i64 + insn.off as i64) as u64; },
            ebpf::JGE_REG    => if  self.reg[dst] >= self.reg[src]                { next_pc = (next_pc as i64 + insn.off as i64) as u64; },
            ebpf::JLT_IMM    => if  self.reg[dst] <  insn.imm as u64              { next_pc = (next_pc as i64 + insn.off as i64) as u64; },
            ebpf::JLT_REG    => if  self.reg[dst] <  self.reg[src]                { next_pc = (next_pc as i64 + insn.off as i64) as u64; },
            ebpf::JLE_IMM    => if  self.reg[dst] <= insn.imm as u64              { next_pc = (next_pc as i64 + insn.off as i64) as u64; },
            ebpf::JLE_REG    => if  self.reg[dst] <= self.reg[src]                { next_pc = (next_pc as i64 + insn.off as i64) as u64; },
            ebpf::JSET_IMM   => if  self.reg[dst] &  insn.imm as u64 != 0         { next_pc = (next_pc as i64 + insn.off as i64) as u64; },
            ebpf::JSET_REG   => if  self.reg[dst] &  self.reg[src] != 0           { next_pc = (next_pc as i64 + insn.off as i64) as u64; },
            ebpf::JNE_IMM    => if  self.reg[dst] != insn.imm as u64              { next_pc = (next_pc as i64 + insn.off as i64) as u64; },
            ebpf::JNE_REG    => if  self.reg[dst] != self.reg[src]                { next_pc = (next_pc as i64 + insn.off as i64) as u64; },
            ebpf::JSGT_IMM   => if (self.reg[dst] as i64) >  insn.imm             { next_pc = (next_pc as i64 + insn.off as i64) as u64; },
            ebpf::JSGT_REG   => if (self.reg[dst] as i64) >  self.reg[src] as i64 { next_pc = (next_pc as i64 + insn.off as i64) as u64; },
            ebpf::JSGE_IMM   => if (self.reg[dst] as i64) >= insn.imm             { next_pc = (next_pc as i64 + insn.off as i64) as u64; },
            ebpf::JSGE_REG   => if (self.reg[dst] as i64) >= self.reg[src] as i64 { next_pc = (next_pc as i64 + insn.off as i64) as u64; },
            ebpf::JSLT_IMM   => if (self.reg[dst] as i64) <  insn.imm             { next_pc = (next_pc as i64 + insn.off as i64) as u64; },
            ebpf::JSLT_REG   => if (self.reg[dst] as i64) <  self.reg[src] as i64 { next_pc = (next_pc as i64 + insn.off as i64) as u64; },
            ebpf::JSLE_IMM   => if (self.reg[dst] as i64) <= insn.imm             { next_pc = (next_pc as i64 + insn.off as i64) as u64; },
            ebpf::JSLE_REG   => if (self.reg[dst] as i64) <= self.reg[src] as i64 { next_pc = (next_pc as i64 + insn.off as i64) as u64; },

            ebpf::CALL_REG   => {
                let target_pc = if self.executable.get_sbpf_version().callx_uses_src_reg() {
                    self.reg[src]
                } else {
                    self.reg[insn.imm as usize]
                };
                if !self.push_frame(config) {
                    return false;
                }
                check_pc!(self, next_pc, target_pc.wrapping_sub(self.program_vm_addr) / ebpf::INSN_SIZE as u64);
                if self.executable.get_sbpf_version().enable_stricter_verification() &&
                    !ebpf::get_insn_unchecked(self.program, next_pc as usize).is_function_start_marker() {
                    throw_error!(self, EbpfError::UnsupportedInstruction);
                }
            },

            // Do not delegate the check to the verifier, since self.registered functions can be
            // changed after the program has been verified.
            ebpf::CALL_IMM => {
                let key = self
                    .executable
                    .get_sbpf_version()
                    .calculate_call_imm_target_pc(self.reg[11] as usize, insn.imm);
                if self.executable.get_sbpf_version().static_syscalls() {
                    // make BPF to BPF call
                    if !self.push_frame(config) {
                        return false;
                    }
                    check_pc!(self, next_pc, key as u64);
                } else if let Some((_, function)) = self.executable.get_loader().get_function_registry().lookup_by_key(insn.imm as u32) {
                    // SBPFv0 syscall
                    self.reg[0] = match self.dispatch_syscall(function) {
                        ProgramResult::Ok(value) => *value,
                        ProgramResult::Err(_err) => return false,
                    };
                } else if let Some((_, target_pc)) =
                    self.executable
                    .get_function_registry()
                    .lookup_by_key(key) {
                    // make BPF to BPF call
                    if !self.push_frame(config) {
                        return false;
                    }
                    check_pc!(self, next_pc, target_pc as u64);
                } else {
                    throw_error!(self, EbpfError::UnsupportedInstruction);
                }
            }
            ebpf::SYSCALL if self.executable.get_sbpf_version().static_syscalls() => {
                if let Some((_, function)) = self.executable.get_loader().get_function_registry().lookup_by_key(insn.imm as u32) {
                    // SBPFv3 syscall
                    self.reg[0] = match self.dispatch_syscall(function) {
                        ProgramResult::Ok(value) => *value,
                        ProgramResult::Err(_err) => return false,
                    };
                } else {
                    debug_assert!(false, "Invalid syscall should have been detected in the verifier.");
                }
            },
            ebpf::RETURN
            | ebpf::EXIT       => {
                if (insn.opc == ebpf::EXIT && self.executable.get_sbpf_version().static_syscalls())
                    || (insn.opc == ebpf::RETURN && !self.executable.get_sbpf_version().static_syscalls()) {
                    throw_error!(self, EbpfError::UnsupportedInstruction);
                }

                if self.vm.call_depth == 0 {
                    if config.enable_instruction_meter && self.vm.due_insn_count > self.vm.previous_instruction_meter {
                        throw_error!(self, EbpfError::ExceededMaxInstructions);
                    }
                    self.vm.program_result = ProgramResult::Ok(self.reg[0]);
                    return false;
                }
                // Return from BPF to BPF call
                self.vm.call_depth -= 1;
                let frame = &self.vm.call_frames[self.vm.call_depth as usize];
                self.reg[ebpf::FRAME_PTR_REG] = frame.frame_pointer;
                self.reg[ebpf::FIRST_SCRATCH_REG
                    ..ebpf::FIRST_SCRATCH_REG + ebpf::SCRATCH_REGS]
                    .copy_from_slice(&frame.caller_saved_registers);
                check_pc!(self, next_pc, frame.target_pc);
            }
            _ => throw_error!(self, EbpfError::UnsupportedInstruction),
        }

        self.reg[11] = next_pc;
        true
    }

    fn dispatch_syscall(&mut self, function: BuiltinFunction<C>) -> &ProgramResult {
        self.vm.due_insn_count = self.vm.previous_instruction_meter - self.vm.due_insn_count;
        self.vm.registers[0..6].copy_from_slice(&self.reg[0..6]);
        self.vm.invoke_function(function);
        self.vm.due_insn_count = 0;
        &self.vm.program_result
    }
}

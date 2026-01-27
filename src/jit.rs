//! Just-in-time compiler (Linux x86, macOS x86)

// Derived from uBPF <https://github.com/iovisor/ubpf>
// Copyright 2015 Big Switch Networks, Inc
//      (uBPF: JIT algorithm, originally in C)
// Copyright 2016 6WIND S.A. <quentin.monnet@6wind.com>
//      (Translation to Rust, MetaBuff addition)
// Copyright 2020 Solana Maintainers <maintainers@solana.com>
//
// Licensed under the Apache License, Version 2.0 <http://www.apache.org/licenses/LICENSE-2.0> or
// the MIT license <http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

#![allow(clippy::arithmetic_side_effects)]

#[cfg(not(feature = "shuttle-test"))]
use rand::{thread_rng, Rng};
#[cfg(feature = "shuttle-test")]
use shuttle::rand::{thread_rng, Rng};

use rand::{
    distributions::{Distribution, Uniform},
    rngs::SmallRng,
    SeedableRng,
};
use std::{fmt::Debug, mem, ptr};

use crate::{
    ebpf::{self, FIRST_SCRATCH_REG, FRAME_PTR_REG, INSN_SIZE, SCRATCH_REGS},
    elf::Executable,
    error::{EbpfError, ProgramResult},
    memory_management::{
        allocate_pages, free_pages, get_system_page_size, protect_pages, round_to_page_size,
    },
    memory_region::{AccessType, MemoryMapping},
    riscv::*,
    vm::{get_runtime_environment_key, Config, ContextObject, EbpfVm, RuntimeEnvironmentSlot},
};

/// The maximum machine code length in bytes of a program with no guest instructions
pub const MAX_EMPTY_PROGRAM_MACHINE_CODE_LENGTH: usize = 4096;
/// The maximum machine code length in bytes of a single guest instruction
pub const MAX_MACHINE_CODE_LENGTH_PER_INSTRUCTION: usize = 32; // In RISC-V, the machine code length of each instruction is 32 bits
/// The maximum machine code length in bytes of an instruction meter checkpoint
pub const MACHINE_CODE_PER_INSTRUCTION_METER_CHECKPOINT: usize = 13;
/// The maximum machine code length of the randomized padding
pub const MAX_START_PADDING_LENGTH: usize = 256;

/// The program compiled to native host machinecode
pub struct JitProgram {
    /// OS page size in bytes and the alignment of the sections
    pub page_size: usize,
    /// Byte offset in the text_section for each BPF instruction
    pub pc_section: &'static mut [u32],
    /// The RISC-V machinecode
    pub text_section: &'static mut [u8],
    /// Number of emitted host machine instructions
    pub machine_instruction_count: usize,
}

impl JitProgram {
    fn new(pc: usize, code_size: usize) -> Result<Self, EbpfError> {
        let page_size = get_system_page_size();
        let pc_loc_table_size = round_to_page_size(pc * std::mem::size_of::<u32>(), page_size);
        let over_allocated_code_size = round_to_page_size(code_size, page_size);
        unsafe {
            let raw = allocate_pages(pc_loc_table_size + over_allocated_code_size)?;
            Ok(Self {
                page_size,
                pc_section: std::slice::from_raw_parts_mut(raw.cast::<u32>(), pc),
                text_section: std::slice::from_raw_parts_mut(
                    raw.add(pc_loc_table_size),
                    over_allocated_code_size,
                ),
                machine_instruction_count: 0,
            })
        }
    }

    fn seal(&mut self, text_section_usage: usize) -> Result<(), EbpfError> {
        if self.page_size == 0 {
            return Ok(());
        }
        let raw = self.pc_section.as_ptr() as *mut u8;
        let pc_loc_table_size =
            round_to_page_size(std::mem::size_of_val(self.pc_section), self.page_size);
        let over_allocated_code_size = round_to_page_size(self.text_section.len(), self.page_size);
        let code_size = round_to_page_size(text_section_usage, self.page_size);
        unsafe {
            // Fill with debugger traps
            std::ptr::write_bytes(
                raw.add(pc_loc_table_size).add(text_section_usage),
                0xcc,
                code_size - text_section_usage,
            );
            if over_allocated_code_size > code_size {
                free_pages(
                    raw.add(pc_loc_table_size).add(code_size),
                    over_allocated_code_size - code_size,
                )?;
            }
            self.text_section =
                std::slice::from_raw_parts_mut(raw.add(pc_loc_table_size), text_section_usage);
            protect_pages(
                self.pc_section.as_mut_ptr().cast::<u8>(),
                pc_loc_table_size,
                false,
            )?;
            protect_pages(self.text_section.as_mut_ptr(), code_size, true)?;
        }
        Ok(())
    }

    pub(crate) fn invoke<C: ContextObject>(
        &self,
        _config: &Config,
        vm: &mut EbpfVm<C>,
        registers: [u64; 12],
    ) {
        unsafe {
            let runtime_environment = std::ptr::addr_of_mut!(*vm)
                .cast::<u64>()
                .offset(get_runtime_environment_key() as isize);
            let instruction_meter =
                (vm.previous_instruction_meter as i64).wrapping_add(registers[11] as i64);
            let entrypoint = &self.text_section
                [self.pc_section[registers[11] as usize] as usize & (i32::MAX as u32 as usize)]
                as *const u8;
            macro_rules! stmt_expr_attribute_asm {
                ($($prologue:literal,)+ cfg(not(feature = $feature:literal)), $guarded:tt, $($epilogue:tt)+) => {
                    #[cfg(feature = $feature)]
                    std::arch::asm!($($prologue,)+ $($epilogue)+);
                    #[cfg(not(feature = $feature))]
                    std::arch::asm!($($prologue,)+ $guarded, $($epilogue)+);
                }
            }
            stmt_expr_attribute_asm!(
                "addi sp, sp, -16",                // push s0 and s1
                "sd s1, 8(sp)",
                "sd s0, 0(sp)",
                "sd sp, 0({host_stack_pointer})",  // host_stack_pointer needn't -8, because jarl don't push ra

                cfg(not(feature = "jit-enable-host-stack-frames")),
                "xor s0, s0, s0",

                "ld a0, 0(a7)",
                "ld a1, 8(a7)",
                "ld a2, 16(a7)",
                "ld a3, 24(a7)",
                "ld a4, 32(a7)",
                "ld a5, 40(a7)",
                "ld s1, 48(a7)",
                "ld s2, 56(a7)",
                "ld s3, 64(a7)",
                "ld s4, 72(a7)",
                "ld s5, 80(a7)",
                "ld a7, 88(a7)",
                // call the JITed code
                "1: auipc t2, %pcrel_hi(2f)",
                "addi t2, t2, %pcrel_lo(1b)",
                "mv s6, t2",                       // save return address in s6
                "jalr ra, s7",
                "2:",

                // pop s0 and s1
                "ld s1, 8(sp)",
                "ld s0, 0(sp)",
                "addi sp, sp, 16",

                host_stack_pointer = in(reg) &mut vm.host_stack_pointer,
                inlateout("s10") runtime_environment => _,
                inlateout("a6") instruction_meter => _,
                inlateout("s7") entrypoint => _,
                inlateout("a7") &registers => _,
                lateout("a1") _, lateout("a2") _, lateout("a3") _, lateout("a4") _,
                lateout("a5") _, lateout("s2") _, lateout("s3") _, lateout("s4") _, lateout("s5") _,
            );
        }
    }

    /// The length of the host machinecode in bytes
    pub fn machine_code_length(&self) -> usize {
        self.text_section.len()
    }

    /// The number of emitted host machine instructions
    pub fn machine_instruction_count(&self) -> usize {
        self.machine_instruction_count
    }

    /// The total memory used in bytes rounded up to page boundaries
    pub fn mem_size(&self) -> usize {
        let pc_loc_table_size =
            round_to_page_size(std::mem::size_of_val(self.pc_section), self.page_size);
        let code_size = round_to_page_size(self.text_section.len(), self.page_size);
        pc_loc_table_size + code_size
    }
}

impl Drop for JitProgram {
    fn drop(&mut self) {
        let pc_loc_table_size =
            round_to_page_size(std::mem::size_of_val(self.pc_section), self.page_size);
        let code_size = round_to_page_size(self.text_section.len(), self.page_size);
        if pc_loc_table_size + code_size > 0 {
            unsafe {
                let _ = free_pages(
                    self.pc_section.as_ptr() as *mut u8,
                    pc_loc_table_size + code_size,
                );
            }
        }
    }
}

impl Debug for JitProgram {
    fn fmt(&self, fmt: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        fmt.write_fmt(format_args!("JitProgram {:?}", self as *const _))
    }
}

impl PartialEq for JitProgram {
    fn eq(&self, other: &Self) -> bool {
        std::ptr::eq(self as *const _, other as *const _)
    }
}

// Used to define subroutines and then call them
// See JitCompiler::set_anchor() and JitCompiler::relative_to_anchor()
const ANCHOR_TRACE: usize = 0;
const ANCHOR_THROW_EXCEEDED_MAX_INSTRUCTIONS: usize = 1;
const ANCHOR_EPILOGUE: usize = 2;
const ANCHOR_THROW_EXCEPTION_UNCHECKED: usize = 3;
const ANCHOR_EXIT: usize = 4;
const ANCHOR_THROW_EXCEPTION: usize = 5;
const ANCHOR_CALL_DEPTH_EXCEEDED: usize = 6;
const ANCHOR_CALL_REG_OUTSIDE_TEXT_SEGMENT: usize = 7;
const ANCHOR_DIV_BY_ZERO: usize = 8;
const ANCHOR_DIV_OVERFLOW: usize = 9;
const ANCHOR_CALL_REG_UNSUPPORTED_INSTRUCTION: usize = 10;
const ANCHOR_CALL_UNSUPPORTED_INSTRUCTION: usize = 11;
const ANCHOR_EXTERNAL_FUNCTION_CALL: usize = 12;
const ANCHOR_INTERNAL_FUNCTION_CALL_PROLOGUE: usize = 13;
const ANCHOR_INTERNAL_FUNCTION_CALL_REG: usize = 14;
const ANCHOR_TRANSLATE_MEMORY_ADDRESS: usize = 21;
const ANCHOR_COUNT: usize = 34; // Update me when adding or removing anchors

const REGISTER_MAP: [u8; 11] = [
    CALLER_SAVED_REGISTERS[4], //a0
    ARGUMENT_REGISTERS[1],     //a1
    ARGUMENT_REGISTERS[2],     //a2
    ARGUMENT_REGISTERS[3],     //a3
    ARGUMENT_REGISTERS[4],     //a4
    ARGUMENT_REGISTERS[5],     //a5
    CALLEE_SAVED_REGISTERS[1], //s1
    CALLEE_SAVED_REGISTERS[2], //s2
    CALLEE_SAVED_REGISTERS[3], //s3
    CALLEE_SAVED_REGISTERS[4], //s4
    CALLEE_SAVED_REGISTERS[5], //s5
];

/// S10: Used together with slot_in_vm()
const REGISTER_PTR_TO_VM: u8 = S10;
/// A6: Program counter limit
const REGISTER_INSTRUCTION_METER: u8 = CALLER_SAVED_REGISTERS[7];
/// A7: Scratch register
const REGISTER_SCRATCH: u8 = CALLER_SAVED_REGISTERS[8];

/// Bit width of an instruction operand
#[derive(Copy, Clone, Debug, PartialEq)]
pub enum OperandSize {
    /// Empty
    S0 = 0,
    /// 8 bit
    S8 = 8,
    /// 16 bit
    S16 = 16,
    /// 32 bit
    S32 = 32,
    /// 64 bit
    S64 = 64,
}

enum Value {
    Register(u8),
    RegisterIndirect(u8, i32, bool),
    RegisterPlusConstant32(u8, i32, bool),
    RegisterPlusConstant64(u8, i64, bool),
    Constant64(i64, bool),
}

struct Argument {
    index: usize,
    value: Value,
}

#[derive(Debug)]
struct Jump {
    location: *const u8,
    target_pc: usize,
}

/* Explanation of the Instruction Meter

    The instruction meter serves two purposes: First, measure how many BPF instructions are
    executed (profiling) and second, limit this number by stopping the program with an exception
    once a given threshold is reached (validation). One approach would be to increment and
    validate the instruction meter before each instruction. However, this would heavily impact
    performance. Thus, we only profile and validate the instruction meter at branches.

    For this, we implicitly sum up all the instructions between two branches.
    It is easy to know the end of such a slice of instructions, but how do we know where it
    started? There could be multiple ways to jump onto a path which all lead to the same final
    branch. This is, where the integral technique comes in. The program is basically a sequence
    of instructions with the x-axis being the program counter (short "pc"). The cost function is
    a constant function which returns one for every point on the x axis. Now, the instruction
    meter needs to calculate the definite integral of the cost function between the start and the
    end of the current slice of instructions. For that we need the indefinite integral of the cost
    function. Fortunately, the derivative of the pc is the cost function (it increases by one for
    every instruction), thus the pc is an antiderivative of the the cost function and a valid
    indefinite integral. So, to calculate an definite integral of the cost function, we just need
    to subtract the start pc from the end pc of the slice. This difference can then be subtracted
    from the remaining instruction counter until it goes below zero at which point it reaches
    the instruction meter limit. Ok, but how do we know the start of the slice at the end?

    The trick is: We do not need to know. As subtraction and addition are associative operations,
    we can reorder them, even beyond the current branch. Thus, we can simply account for the
    amount the start will subtract at the next branch by already adding that to the remaining
    instruction counter at the current branch. So, every branch just subtracts its current pc
    (the end of the slice) and adds the target pc (the start of the next slice) to the remaining
    instruction counter. This way, no branch needs to know the pc of the last branch explicitly.
    Another way to think about this trick is as follows: The remaining instruction counter now
    measures what the maximum pc is, that we can reach with the remaining budget after the last
    branch.

    One problem are conditional branches. There are basically two ways to handle them: Either,
    only do the profiling if the branch is taken, which requires two jumps (one for the profiling
    and one to get to the target pc). Or, always profile it as if the jump to the target pc was
    taken, but then behind the conditional branch, undo the profiling (as it was not taken). We
    use the second method and the undo profiling is the same as the normal profiling, just with
    reversed plus and minus signs.

    Another special case to keep in mind are return instructions. They would require us to know
    the return address (target pc), but in the JIT we already converted that to be a host address.
    Of course, one could also save the BPF return address on the stack, but an even simpler
    solution exists: Just count as if you were jumping to an specific target pc before the exit,
    and then after returning use the undo profiling. The trick is, that the undo profiling now
    has the current pc which is the BPF return address. The virtual target pc we count towards
    and undo again can be anything, so we just set it to zero.
*/

/// Temporary object which stores the compilation context
pub struct JitCompiler<'a, C: ContextObject> {
    result: JitProgram,
    text_section_jumps: Vec<Jump>,
    anchors: [*const u8; ANCHOR_COUNT],
    offset_in_text_section: usize,
    executable: &'a Executable<C>,
    program: &'a [u8],
    program_vm_addr: u64,
    config: &'a Config,
    pc: usize,
    last_instruction_meter_validation_pc: usize,
    next_noop_insertion: u32,
    noop_range: Uniform<u32>,
    runtime_environment_key: i32,
    immediate_value_key: i64,
    diversification_rng: SmallRng,
    stopwatch_is_active: bool,
}

#[rustfmt::skip]
impl<'a, C: ContextObject> JitCompiler<'a, C> {
    /// Constructs a new compiler and allocates memory for the compilation output
    pub fn new(executable: &'a Executable<C>)->Result<Self,EbpfError>{
        let config = executable.get_config();
        let (program_vm_addr, program) = executable.get_text_bytes();

        // Scan through program to find actual number of instructions
        let mut pc = 0;
        if !executable.get_sbpf_version().disable_lddw() {
            while (pc + 1) * ebpf::INSN_SIZE <= program.len() {
                let insn = ebpf::get_insn_unchecked(program, pc);
                pc += match insn.opc {
                    ebpf::LD_DW_IMM => 2,
                    _ => 1,
                };
            }
        } else {
            pc = program.len() / ebpf::INSN_SIZE;
        }

        let mut code_length_estimate = MAX_EMPTY_PROGRAM_MACHINE_CODE_LENGTH + MAX_START_PADDING_LENGTH + MAX_MACHINE_CODE_LENGTH_PER_INSTRUCTION * pc;
        if config.noop_instruction_rate != 0 {
            code_length_estimate += code_length_estimate / config.noop_instruction_rate as usize;
        }
        if config.instruction_meter_checkpoint_distance != 0 {
            code_length_estimate += pc / config.instruction_meter_checkpoint_distance * MACHINE_CODE_PER_INSTRUCTION_METER_CHECKPOINT;
        }
        // Relative jump destinations limit the maximum output size
        debug_assert!(code_length_estimate < (i32::MAX as usize));

        let runtime_environment_key = get_runtime_environment_key();
        let mut diversification_rng = SmallRng::from_rng(thread_rng()).map_err(|_| EbpfError::JitNotCompiled)?;
        // let immediate_value_key = diversification_rng.gen::<i64>();
        let immediate_value_key = 0; // fixed value to avoid the influence of the sanitization of immediate values on the performance measurements of the JIT

        Ok(Self {
            result: JitProgram::new(pc, code_length_estimate)?,
            text_section_jumps: vec![],
            anchors: [std::ptr::null(); ANCHOR_COUNT],
            offset_in_text_section: 0,
            executable,
            program_vm_addr,
            program,
            config,
            pc: 0,
            last_instruction_meter_validation_pc: 0,
            next_noop_insertion: if config.noop_instruction_rate == 0 { u32::MAX } else { diversification_rng.gen_range(0..config.noop_instruction_rate * 2) },
            noop_range: Uniform::new_inclusive(0, config.noop_instruction_rate * 2),
            runtime_environment_key,
            immediate_value_key,
            diversification_rng,
            stopwatch_is_active: false,
        })
    }

    /// Compiles the given executable, consuming the compiler
    pub fn compile(mut self) -> Result<JitProgram, EbpfError> {
        // Randomized padding at the start before random intervals begin
        // if self.config.noop_instruction_rate != 0 {
        //     for _ in 0..self.diversification_rng.gen_range(0..MAX_START_PADDING_LENGTH) {
        //         // RISCVInstruction::noop().emit(self)?;
        //         self.emit_ins(RISCVInstruction::addi(OperandSize::S64, ZERO, 0, ZERO));
        //     }
        // }
        
        self.emit_subroutines();

        while self.pc * ebpf::INSN_SIZE < self.program.len(){
            if self.offset_in_text_section + MAX_MACHINE_CODE_LENGTH_PER_INSTRUCTION * 2 >= self.result.text_section.len() {
                return Err(EbpfError::ExhaustedTextSegment(self.pc));
            }
            let mut insn = ebpf::get_insn_unchecked(self.program, self.pc);
            self.result.pc_section[self.pc] = self.offset_in_text_section as u32;

            // Regular instruction meter checkpoints to prevent long linear runs from exceeding their budget
            if self.last_instruction_meter_validation_pc + self.config.instruction_meter_checkpoint_distance <= self.pc {
                self.emit_validate_instruction_count(Some(self.pc));
            }
            
            if self.config.enable_register_tracing {
                self.load_immediate(OperandSize::S64, REGISTER_SCRATCH, self.pc as i64);
                self.emit_ins(RISCVInstruction::addi(OperandSize::S64, SP, -8, SP));
                self.store(OperandSize::S64, SP, RA, 0);
                self.emit_ins(RISCVInstruction::jal(self.relative_to_anchor(ANCHOR_TRACE, 0), RA));
                self.load(OperandSize::S64, SP, 0, RA);
                self.emit_ins(RISCVInstruction::addi(OperandSize::S64, SP, 8, SP));
                self.emit_ins(RISCVInstruction::mov(OperandSize::S64, ZERO, REGISTER_SCRATCH));
            }

            let dst = REGISTER_MAP[insn.dst as usize];
            let src = REGISTER_MAP[insn.src as usize];
            let target_pc = (self.pc as isize + insn.off as isize + 1) as usize;
            match insn.opc{
                ebpf::LD_DW_IMM if !self.executable.get_sbpf_version().disable_lddw() => {
                    self.emit_validate_and_profile_instruction_count(Some(self.pc + 2));
                    self.pc += 1;
                    self.result.pc_section[self.pc] = unsafe { self.anchors[ANCHOR_CALL_UNSUPPORTED_INSTRUCTION].offset_from(self.result.text_section.as_ptr()) as u32 };
                    ebpf::augment_lddw_unchecked(self.program, &mut insn);
                    if self.should_sanitize_constant(insn.imm) {
                        self.emit_sanitized_load_immediate(dst, insn.imm);
                    } else {
                        self.load_immediate(OperandSize::S64, dst, insn.imm);
                    }
                }

                // BPF_LDX class
                ebpf::LD_B_REG   if !self.executable.get_sbpf_version().move_memory_instruction_classes() =>  {
                    self.emit_address_translation(Some(dst), Value::RegisterPlusConstant64(src, insn.off as i64, true), 1, None);
                },
                ebpf::LD_H_REG   if !self.executable.get_sbpf_version().move_memory_instruction_classes() =>  {
                    self.emit_address_translation(Some(dst), Value::RegisterPlusConstant64(src, insn.off as i64, true), 2, None);
                },
                ebpf::LD_W_REG   if !self.executable.get_sbpf_version().move_memory_instruction_classes() =>  {
                    self.emit_address_translation(Some(dst), Value::RegisterPlusConstant64(src, insn.off as i64, true), 4, None);
                },
                ebpf::LD_DW_REG  if !self.executable.get_sbpf_version().move_memory_instruction_classes() =>  {
                    self.emit_address_translation(Some(dst), Value::RegisterPlusConstant64(src, insn.off as i64, true), 8, None);
                },

                // BPF_ST class
                ebpf::ST_B_IMM   if !self.executable.get_sbpf_version().move_memory_instruction_classes() =>  {
                    self.emit_address_translation(None, Value::RegisterPlusConstant64(dst, insn.off as i64, true), 1, Some(Value::Constant64(insn.imm, true)));
                },
                ebpf::ST_H_IMM   if !self.executable.get_sbpf_version().move_memory_instruction_classes() =>  {
                    self.emit_address_translation(None, Value::RegisterPlusConstant64(dst, insn.off as i64, true), 2, Some(Value::Constant64(insn.imm, true)));
                },
                ebpf::ST_W_IMM   if !self.executable.get_sbpf_version().move_memory_instruction_classes() =>  {
                    self.emit_address_translation(None, Value::RegisterPlusConstant64(dst, insn.off as i64, true), 4, Some(Value::Constant64(insn.imm, true)));
                },
                ebpf::ST_DW_IMM  if !self.executable.get_sbpf_version().move_memory_instruction_classes() =>  {
                    self.emit_address_translation(None, Value::RegisterPlusConstant64(dst, insn.off as i64, true), 8, Some(Value::Constant64(insn.imm, true)));
                },

                // BPF_STX class
                ebpf::ST_B_REG  if !self.executable.get_sbpf_version().move_memory_instruction_classes() =>  {
                    self.emit_address_translation(None, Value::RegisterPlusConstant64(dst, insn.off as i64, true), 1, Some(Value::Register(src)));
                },
                ebpf::ST_H_REG  if !self.executable.get_sbpf_version().move_memory_instruction_classes() =>  {
                    self.emit_address_translation(None, Value::RegisterPlusConstant64(dst, insn.off as i64, true), 2, Some(Value::Register(src)));
                },
                ebpf::ST_W_REG  if !self.executable.get_sbpf_version().move_memory_instruction_classes() =>  {
                    self.emit_address_translation(None, Value::RegisterPlusConstant64(dst, insn.off as i64, true), 4, Some(Value::Register(src)));
                },
                ebpf::ST_DW_REG  if !self.executable.get_sbpf_version().move_memory_instruction_classes() =>  {
                    self.emit_address_translation(None, Value::RegisterPlusConstant64(dst, insn.off as i64, true), 8, Some(Value::Register(src)));
                },

                // BPF_ALU class
                ebpf::ADD32_IMM  => {
                    self.emit_sanitized_add(OperandSize::S32, dst, insn.imm as i32 as i64);
                }
                ebpf::ADD32_REG  => {
                    self.emit_ins(RISCVInstruction::addw(OperandSize::S32, src, dst, dst));
                }
                ebpf::SUB32_IMM  => {
                    if self.executable.get_sbpf_version().swap_sub_reg_imm_operands() {
                        self.emit_ins(RISCVInstruction::subw(OperandSize::S32, ZERO, dst, dst));
                        if insn.imm != 0{
                            self.emit_sanitized_add(OperandSize::S32, dst, insn.imm as i32 as i64);
                        }
                    } else {
                        self.emit_sanitized_sub(OperandSize::S32, dst, insn.imm as i32 as i64);
                    }
                }
                ebpf::SUB32_REG  => {
                    self.emit_ins(RISCVInstruction::subw(OperandSize::S32, dst, src, dst));
                }
                ebpf::MUL32_IMM if !self.executable.get_sbpf_version().enable_pqr() => {
                    if self.should_sanitize_constant(insn.imm) {
                        self.emit_sanitized_load_immediate(REGISTER_SCRATCH, insn.imm);
                    } else {
                        self.load_immediate(OperandSize::S32, REGISTER_SCRATCH, insn.imm);
                    }
                    self.emit_ins(RISCVInstruction::mulw(OperandSize::S32, dst, REGISTER_SCRATCH, dst));
                }
                ebpf::DIV32_IMM if !self.executable.get_sbpf_version().enable_pqr() => {
                    self.load_immediate(OperandSize::S32, T1, insn.imm);
                    self.div_err_handle(OperandSize::S32, false, T1, dst);
                    self.emit_ins(RISCVInstruction::divuw(OperandSize::S32, dst, T1, dst));
                    self.zero_extend(dst);
                }
                ebpf::MOD32_IMM if !self.executable.get_sbpf_version().enable_pqr() => {
                    self.load_immediate(OperandSize::S32, T1, insn.imm);
                    self.div_err_handle(OperandSize::S32, false, T1, dst);
                    self.emit_ins(RISCVInstruction::remuw(OperandSize::S32, dst, T1, dst));
                    self.zero_extend(dst);
                }
                ebpf::LD_1B_REG  if self.executable.get_sbpf_version().move_memory_instruction_classes() => {
                    self.emit_address_translation(Some(dst), Value::RegisterPlusConstant64(src, insn.off as i64, true), 1, None);
                },
                ebpf::MUL32_REG if !self.executable.get_sbpf_version().enable_pqr() => {
                    self.emit_ins(RISCVInstruction::mulw(OperandSize::S32, dst, src, dst));
                }
                ebpf::DIV32_REG if !self.executable.get_sbpf_version().enable_pqr() => {
                    self.div_err_handle(OperandSize::S32, false, src, dst);
                    self.emit_ins(RISCVInstruction::divuw(OperandSize::S32, dst, src, dst));
                    self.zero_extend(dst);
                }
                ebpf::MOD32_REG if !self.executable.get_sbpf_version().enable_pqr() => {
                    self.div_err_handle(OperandSize::S32, false, src, dst);
                    self.emit_ins(RISCVInstruction::remuw(OperandSize::S32, dst, src, dst));
                    self.zero_extend(dst);
                }
                ebpf::LD_2B_REG  if self.executable.get_sbpf_version().move_memory_instruction_classes() => {
                    self.emit_address_translation(Some(dst), Value::RegisterPlusConstant64(src, insn.off as i64, true), 2, None);
                },
                ebpf::OR32_IMM   => {
                    self.emit_sanitized_or(OperandSize::S32, dst, insn.imm);
                    self.zero_extend(dst);
                }
                ebpf::OR32_REG   => {
                    self.emit_ins(RISCVInstruction::or(OperandSize::S32, dst, src, dst));
                    self.zero_extend(dst);
                }
                ebpf::AND32_IMM  => {
                    self.emit_sanitized_and(OperandSize::S32, dst, insn.imm);
                    self.zero_extend(dst);
                }
                ebpf::AND32_REG  => {
                    self.emit_ins(RISCVInstruction::and(OperandSize::S32, dst, src, dst));
                    self.zero_extend(dst);
                }
                ebpf::LSH32_IMM  => {
                    self.emit_ins(RISCVInstruction::slliw(OperandSize::S32, dst, insn.imm, dst));
                    self.zero_extend(dst);
                }
                ebpf::LSH32_REG  => {
                    self.emit_ins(RISCVInstruction::sllw(OperandSize::S32, dst, src, dst));
                    self.zero_extend(dst);
                }
                ebpf::RSH32_IMM  => {
                    self.emit_ins(RISCVInstruction::srliw(OperandSize::S32, dst, insn.imm, dst));
                    self.zero_extend(dst);
                }
                ebpf::RSH32_REG  => {
                    self.emit_ins(RISCVInstruction::srlw(OperandSize::S32, dst, src, dst));
                    self.zero_extend(dst);
                }
                ebpf::NEG32     if !self.executable.get_sbpf_version().disable_neg() => {
                    self.emit_ins(RISCVInstruction::sub(OperandSize::S32, ZERO, dst, dst));
                    self.zero_extend(dst);
                }
                ebpf::LD_4B_REG  if self.executable.get_sbpf_version().move_memory_instruction_classes() => {
                    self.emit_address_translation(Some(dst), Value::RegisterPlusConstant64(src, insn.off as i64, true), 4, None);
                },
                ebpf::LD_8B_REG  if self.executable.get_sbpf_version().move_memory_instruction_classes() => {
                    self.emit_address_translation(Some(dst), Value::RegisterPlusConstant64(src, insn.off as i64, true), 8, None);
                },
                ebpf::XOR32_IMM  => {
                    self.emit_sanitized_xor(OperandSize::S32, dst, insn.imm);
                    self.zero_extend(dst);
                }
                ebpf::XOR32_REG  => {
                    self.emit_ins(RISCVInstruction::xor(OperandSize::S32, dst, src, dst));
                    self.zero_extend(dst);
                }
                ebpf::MOV32_IMM  => {
                    if self.should_sanitize_constant(insn.imm) {
                        self.emit_sanitized_load_immediate(dst, insn.imm as u32 as u64 as i64);
                    } else {
                        self.load_immediate(OperandSize::S64, dst, insn.imm as u32 as u64 as i64);
                    }
                }
                ebpf::MOV32_REG  => {
                    self.emit_ins(RISCVInstruction::mov(OperandSize::S64, src, dst));
                    if !self.executable.get_sbpf_version().explicit_sign_extension_of_results() {
                        self.zero_extend(dst);
                    }
                }
                ebpf::ARSH32_IMM => {
                    self.emit_ins(RISCVInstruction::sraiw(OperandSize::S32, dst, insn.imm, dst));
                    self.zero_extend(dst);
                }
                ebpf::ARSH32_REG => {
                    self.emit_ins(RISCVInstruction::sraw(OperandSize::S32, dst, src, dst));
                    self.zero_extend(dst);
                }
                ebpf::LE if !self.executable.get_sbpf_version().disable_le() => {
                    match insn.imm {
                        16 => {
                            self.load_immediate(OperandSize::S64, T1, 0xffff);
                            self.emit_ins(RISCVInstruction::and(OperandSize::S32, dst, T1, dst)); // Mask to 16 bit
                        }
                        32 => {
                            self.load_immediate(OperandSize::S64, T1, 0xffffffff);
                            self.emit_ins(RISCVInstruction::and(OperandSize::S32, dst, T1, dst)); // Mask to 32 bit
                        }
                        64 => {}
                        _ => {
                            return Err(EbpfError::InvalidInstruction);
                        }
                    }
                },
                ebpf::BE         => {
                    match insn.imm {
                        16 => {
                            self.emit_ins(RISCVInstruction::andi(OperandSize::S32, dst, 0xff, T1));
                            self.emit_ins(RISCVInstruction::srliw(OperandSize::S32, dst, 8, T2));
                            self.emit_ins(RISCVInstruction::andi(OperandSize::S32, T2, 0xff, T2));
                            self.emit_ins(RISCVInstruction::slliw(OperandSize::S32, T1, 8, T1));
                            self.emit_ins(RISCVInstruction::or(OperandSize::S64, T1, T2, dst));
                        }
                        32 => {
                            self.emit_ins(RISCVInstruction::andi(OperandSize::S32, dst, 0xff, T1));
                            self.emit_ins(RISCVInstruction::srliw(OperandSize::S32, dst, 8, T2));
                            self.emit_ins(RISCVInstruction::andi(OperandSize::S32, T2, 0xff, T2));
                            self.emit_ins(RISCVInstruction::srliw(OperandSize::S32, dst, 16, T3));
                            self.emit_ins(RISCVInstruction::andi(OperandSize::S32, T3, 0xff, T3));
                            self.emit_ins(RISCVInstruction::srliw(OperandSize::S32, dst, 24, T4));
                            self.emit_ins(RISCVInstruction::andi(OperandSize::S32, T4, 0xff, T4));
                            
                            self.emit_ins(RISCVInstruction::slliw(OperandSize::S32, T1, 24, T1));
                            self.emit_ins(RISCVInstruction::slliw(OperandSize::S32, T2, 16, T2));
                            self.emit_ins(RISCVInstruction::slliw(OperandSize::S32, T3, 8, T3));
                            self.emit_ins(RISCVInstruction::or(OperandSize::S64, T1, T2, dst));
                            self.emit_ins(RISCVInstruction::or(OperandSize::S64, dst, T3, dst));
                            self.emit_ins(RISCVInstruction::or(OperandSize::S64, dst, T4, dst));
                        }
                        64 => {
                            //low32bits
                            self.emit_ins(RISCVInstruction::andi(OperandSize::S64, dst, 0xff, T1));
                            self.emit_ins(RISCVInstruction::srliw(OperandSize::S64, dst, 8, T2));
                            self.emit_ins(RISCVInstruction::andi(OperandSize::S64, T2, 0xff, T2));
                            self.emit_ins(RISCVInstruction::srliw(OperandSize::S64, dst, 16, T3));
                            self.emit_ins(RISCVInstruction::andi(OperandSize::S64, T3, 0xff, T3));
                            self.emit_ins(RISCVInstruction::srliw(OperandSize::S64, dst, 24, T4));
                            self.emit_ins(RISCVInstruction::andi(OperandSize::S64, T4, 0xff, T4));
                            
                            self.emit_ins(RISCVInstruction::slliw(OperandSize::S64, T1, 24, T1));
                            self.emit_ins(RISCVInstruction::slliw(OperandSize::S64, T2, 16, T2));
                            self.emit_ins(RISCVInstruction::slliw(OperandSize::S64, T3, 8, T3));
                            self.emit_ins(RISCVInstruction::or(OperandSize::S64, T1, T2, T5));
                            self.emit_ins(RISCVInstruction::or(OperandSize::S64, T5, T3, T5));
                            self.emit_ins(RISCVInstruction::or(OperandSize::S64, T5, T4, T5));
                            self.emit_ins(RISCVInstruction::slli(OperandSize::S64,T5,32,T5));
                            //high32bits
                            self.emit_ins(RISCVInstruction::srli(OperandSize::S64, dst, 32, T1));
                            self.emit_ins(RISCVInstruction::andi(OperandSize::S64, T1, 0xff, T1));
                            self.emit_ins(RISCVInstruction::srli(OperandSize::S64, dst, 40, T2));
                            self.emit_ins(RISCVInstruction::andi(OperandSize::S64, T2, 0xff, T2));
                            self.emit_ins(RISCVInstruction::srli(OperandSize::S64, dst, 48, T3));
                            self.emit_ins(RISCVInstruction::andi(OperandSize::S64, T3, 0xff, T3));
                            self.emit_ins(RISCVInstruction::srli(OperandSize::S64, dst, 56, T4));
                            self.emit_ins(RISCVInstruction::andi(OperandSize::S64, T4, 0xff, T4));
                        
                            self.emit_ins(RISCVInstruction::slli(OperandSize::S64, T1, 24, T1));
                            self.emit_ins(RISCVInstruction::slli(OperandSize::S64, T2, 16, T2));
                            self.emit_ins(RISCVInstruction::slli(OperandSize::S64, T3, 8, T3));
                            self.emit_ins(RISCVInstruction::or(OperandSize::S64, T5, T1, T5));
                            self.emit_ins(RISCVInstruction::or(OperandSize::S64, T5, T2, T5));
                            self.emit_ins(RISCVInstruction::or(OperandSize::S64, T5, T3, T5));
                            self.emit_ins(RISCVInstruction::or(OperandSize::S64, T5, T4, dst));
                        }
                        _ => {
                            return Err(EbpfError::InvalidInstruction);
                        }
                    }
                },

                // BPF_ALU64 class
                ebpf::ADD64_IMM  => {
                    self.emit_sanitized_add(OperandSize::S64, dst, insn.imm);
                }
                ebpf::ADD64_REG  => {
                    self.emit_ins(RISCVInstruction::add(OperandSize::S64, src, dst, dst));
                }
                ebpf::SUB64_IMM  =>{
                    if self.executable.get_sbpf_version().swap_sub_reg_imm_operands() {
                        self.emit_ins(RISCVInstruction::sub(OperandSize::S64, ZERO, dst, dst));
                        if insn.imm != 0{
                            self.emit_sanitized_add(OperandSize::S64, dst, insn.imm);
                        }
                    } else {
                        self.emit_sanitized_sub(OperandSize::S64, dst, insn.imm);
                    }
                }
                ebpf::SUB64_REG  => {
                    self.emit_ins(RISCVInstruction::sub(OperandSize::S64, dst, src, dst));
                }
                ebpf::MUL64_IMM if !self.executable.get_sbpf_version().enable_pqr() => {
                    if self.should_sanitize_constant(insn.imm) {
                        self.emit_sanitized_load_immediate(REGISTER_SCRATCH, insn.imm);
                    } else {
                        self.load_immediate(OperandSize::S64, REGISTER_SCRATCH, insn.imm);
                    }
                    self.emit_ins(RISCVInstruction::mul(OperandSize::S64, dst, REGISTER_SCRATCH, dst));
                }
                ebpf::DIV64_IMM if !self.executable.get_sbpf_version().enable_pqr() => {
                    self.load_immediate(OperandSize::S64, T1, insn.imm);
                    self.div_err_handle(OperandSize::S64, false, T1, dst);
                    self.emit_ins(RISCVInstruction::divu(OperandSize::S64, dst, T1, dst));
                }
                ebpf::MOD64_IMM if !self.executable.get_sbpf_version().enable_pqr() => {
                    self.load_immediate(OperandSize::S64, T1, insn.imm);
                    self.div_err_handle(OperandSize::S64, false, T1, dst);
                    self.emit_ins(RISCVInstruction::remu(OperandSize::S64, dst, T1, dst));
                }
                ebpf::ST_1B_IMM  if self.executable.get_sbpf_version().move_memory_instruction_classes() => {
                    self.emit_address_translation(None, Value::RegisterPlusConstant64(dst, insn.off as i64, true), 1, Some(Value::Constant64(insn.imm, true)));
                },
                ebpf::ST_2B_IMM  if self.executable.get_sbpf_version().move_memory_instruction_classes() => {
                    self.emit_address_translation(None, Value::RegisterPlusConstant64(dst, insn.off as i64, true), 2, Some(Value::Constant64(insn.imm, true)));
                },
                ebpf::MUL64_REG if !self.executable.get_sbpf_version().enable_pqr() => {
                    self.emit_ins(RISCVInstruction::mul(OperandSize::S64, dst, src, dst));
                }
                ebpf::DIV64_REG if !self.executable.get_sbpf_version().enable_pqr() => {
                    self.div_err_handle(OperandSize::S64, false, src, dst);
                    self.emit_ins(RISCVInstruction::divu(OperandSize::S64, dst, src, dst));
                }
                ebpf::MOD64_REG if !self.executable.get_sbpf_version().enable_pqr() => {
                    self.div_err_handle(OperandSize::S64, false, src, dst);
                    self.emit_ins(RISCVInstruction::remu(OperandSize::S64, dst, src, dst));
                }
                ebpf::ST_1B_REG  if self.executable.get_sbpf_version().move_memory_instruction_classes() => {
                    self.emit_address_translation(None, Value::RegisterPlusConstant64(dst, insn.off as i64, true), 1, Some(Value::Register(src)));
                },
                ebpf::ST_2B_REG  if self.executable.get_sbpf_version().move_memory_instruction_classes() => {
                    self.emit_address_translation(None, Value::RegisterPlusConstant64(dst, insn.off as i64, true), 2, Some(Value::Register(src)));
                },
                ebpf::OR64_IMM   => self.emit_sanitized_or(OperandSize::S64, dst, insn.imm),
                ebpf::OR64_REG   => {
                    self.emit_ins(RISCVInstruction::or(OperandSize::S64, dst, src, dst));
                }
                ebpf::AND64_IMM  => self.emit_sanitized_and(OperandSize::S64, dst, insn.imm),
                ebpf::AND64_REG  => self.emit_ins(RISCVInstruction::and(OperandSize::S64, dst, src, dst)),
                ebpf::LSH64_IMM  => self.emit_ins(RISCVInstruction::slli(OperandSize::S64, dst, insn.imm, dst)),
                ebpf::LSH64_REG  => self.emit_ins(RISCVInstruction::sll(OperandSize::S64, dst, src, dst)),
                ebpf::RSH64_IMM  => self.emit_ins(RISCVInstruction::srli(OperandSize::S64, dst, insn.imm, dst)),
                ebpf::RSH64_REG  => self.emit_ins(RISCVInstruction::srl(OperandSize::S64, dst, src, dst)),
                ebpf::ST_4B_IMM  if self.executable.get_sbpf_version().move_memory_instruction_classes() => {
                    self.emit_address_translation(None, Value::RegisterPlusConstant64(dst, insn.off as i64, true), 4, Some(Value::Constant64(insn.imm, true)));
                },
                ebpf::NEG64     if !self.executable.get_sbpf_version().disable_neg() => self.emit_ins(RISCVInstruction::sub(OperandSize::S64, ZERO, dst, dst)),
                ebpf::ST_4B_REG  if self.executable.get_sbpf_version().move_memory_instruction_classes() => {
                    self.emit_address_translation(None, Value::RegisterPlusConstant64(dst, insn.off as i64, true), 4, Some(Value::Register(src)));
                },
                ebpf::ST_8B_IMM  if self.executable.get_sbpf_version().move_memory_instruction_classes() => {
                    self.emit_address_translation(None, Value::RegisterPlusConstant64(dst, insn.off as i64, true), 8, Some(Value::Constant64(insn.imm, true)));
                },
                ebpf::ST_8B_REG  if self.executable.get_sbpf_version().move_memory_instruction_classes() => {
                    self.emit_address_translation(None, Value::RegisterPlusConstant64(dst, insn.off as i64, true), 8, Some(Value::Register(src)));
                },
                ebpf::XOR64_IMM  => self.emit_sanitized_xor(OperandSize::S64, dst, insn.imm),
                ebpf::XOR64_REG  => self.emit_ins(RISCVInstruction::xor(OperandSize::S64, dst, src, dst)),
                ebpf::MOV64_IMM  => {
                    if self.should_sanitize_constant(insn.imm) {
                        self.emit_sanitized_load_immediate(dst, insn.imm);
                    } else {
                        self.load_immediate(OperandSize::S64, dst, insn.imm);
                    }
                }
                ebpf::MOV64_REG  => self.emit_ins(RISCVInstruction::mov(OperandSize::S64, src, dst)),
                ebpf::ARSH64_IMM => self.emit_ins(RISCVInstruction::srai(OperandSize::S64, dst, insn.imm, dst)),
                ebpf::ARSH64_REG => self.emit_ins(RISCVInstruction::sra(OperandSize::S64, dst, src, dst)),
                ebpf::HOR64_IMM if self.executable.get_sbpf_version().disable_lddw() => {
                    self.emit_sanitized_or(OperandSize::S64, dst, (insn.imm as u64).wrapping_shl(32) as i64);
                }

                // BPF_PQR class
                ebpf::LMUL32_IMM if self.executable.get_sbpf_version().enable_pqr() => {
                    self.load_immediate(OperandSize::S32, T1, insn.imm as u32 as i64);
                    self.emit_ins(RISCVInstruction::mulw(OperandSize::S32, dst, T1, dst));
                    self.zero_extend(dst);
                }
                ebpf::LMUL64_IMM if self.executable.get_sbpf_version().enable_pqr() => {
                    self.load_immediate(OperandSize::S64, T1, insn.imm);
                    self.emit_ins(RISCVInstruction::mul(OperandSize::S64, dst, T1, dst));
                }
                ebpf::UHMUL64_IMM if self.executable.get_sbpf_version().enable_pqr() => {
                    self.load_immediate(OperandSize::S64, T1, insn.imm);
                    self.zero_extend(T1);
                    self.emit_ins(RISCVInstruction::mulhu(OperandSize::S64, dst, T1, dst));
                }
                ebpf::SHMUL64_IMM if self.executable.get_sbpf_version().enable_pqr() => {
                    self.load_immediate(OperandSize::S64, T1, insn.imm);
                    self.emit_ins(RISCVInstruction::mulh(OperandSize::S64, dst, T1, dst));
                }
                ebpf::UDIV32_IMM if self.executable.get_sbpf_version().enable_pqr() => {
                    self.load_immediate(OperandSize::S32, T1, insn.imm);
                    self.div_err_handle(OperandSize::S32, false, T1, dst);
                    self.emit_ins(RISCVInstruction::divuw(OperandSize::S32, dst, T1, dst));
                    self.zero_extend(dst);
                }
                ebpf::UDIV64_IMM if self.executable.get_sbpf_version().enable_pqr() => {
                    self.load_immediate(OperandSize::S64, T1, insn.imm);
                    self.zero_extend(T1);
                    self.div_err_handle(OperandSize::S64, false, T1, dst);
                    self.emit_ins(RISCVInstruction::divu(OperandSize::S64, dst, T1, dst));
                }
                ebpf::UREM32_IMM if self.executable.get_sbpf_version().enable_pqr() => {
                    self.load_immediate(OperandSize::S32, T1, insn.imm);
                    self.zero_extend(T1);
                    self.div_err_handle(OperandSize::S32, false, T1, dst);
                    self.emit_ins(RISCVInstruction::remuw(OperandSize::S32, dst, T1, dst));
                    self.zero_extend(dst);
                }
                ebpf::UREM64_IMM if self.executable.get_sbpf_version().enable_pqr() => {
                    self.load_immediate(OperandSize::S64, T1, insn.imm);
                    self.zero_extend(T1);
                    self.div_err_handle(OperandSize::S64, false, T1, dst);
                    self.emit_ins(RISCVInstruction::remu(OperandSize::S64, dst, T1, dst));
                }
                ebpf::SDIV32_IMM if self.executable.get_sbpf_version().enable_pqr() => {
                    self.load_immediate(OperandSize::S32, T1, insn.imm);
                    self.div_err_handle(OperandSize::S32, true, T1, dst);
                    self.emit_ins(RISCVInstruction::divw(OperandSize::S32, dst, T1, dst));
                    self.zero_extend(dst);
                }
                ebpf::SDIV64_IMM if self.executable.get_sbpf_version().enable_pqr() => {
                    self.load_immediate(OperandSize::S64, T1, insn.imm);
                    self.div_err_handle(OperandSize::S64, true, T1, dst);
                    self.emit_ins(RISCVInstruction::div(OperandSize::S64, dst, T1, dst));
                }
                ebpf::SREM32_IMM if self.executable.get_sbpf_version().enable_pqr() => {
                    self.load_immediate(OperandSize::S32, T1, insn.imm);
                    self.div_err_handle(OperandSize::S32, true, T1, dst);
                    self.emit_ins(RISCVInstruction::remw(OperandSize::S32, dst, T1, dst));
                    self.zero_extend(dst);
                }
                ebpf::SREM64_IMM if self.executable.get_sbpf_version().enable_pqr() => {
                    self.load_immediate(OperandSize::S64, T1, insn.imm);
                    self.div_err_handle(OperandSize::S64, true, T1, dst);
                    self.emit_ins(RISCVInstruction::rem(OperandSize::S64, dst, T1, dst));
                }
                ebpf::LMUL32_REG if self.executable.get_sbpf_version().enable_pqr() => {
                    self.emit_ins(RISCVInstruction::mulw(OperandSize::S32, dst, src, dst));
                    self.zero_extend(dst);
                }
                ebpf::LMUL64_REG if self.executable.get_sbpf_version().enable_pqr() => {
                    self.emit_ins(RISCVInstruction::mul(OperandSize::S64, dst, src, dst));
                }
                ebpf::UHMUL64_REG if self.executable.get_sbpf_version().enable_pqr() => {
                    self.emit_ins(RISCVInstruction::mulhu(OperandSize::S64, dst, src, dst));
                }
                ebpf::SHMUL64_REG if self.executable.get_sbpf_version().enable_pqr() => {
                    self.emit_ins(RISCVInstruction::mulh(OperandSize::S64, dst, src, dst));
                }
                ebpf::UDIV32_REG if self.executable.get_sbpf_version().enable_pqr() => {
                    self.div_err_handle(OperandSize::S32, false, src, dst);
                    self.emit_ins(RISCVInstruction::divuw(OperandSize::S32, dst, src, dst));
                    self.zero_extend(dst);
                }
                ebpf::UDIV64_REG if self.executable.get_sbpf_version().enable_pqr() => {
                    self.div_err_handle(OperandSize::S64, false, src, dst);
                    self.emit_ins(RISCVInstruction::divu(OperandSize::S64, dst, src, dst));
                }
                ebpf::UREM32_REG if self.executable.get_sbpf_version().enable_pqr() => {
                    self.div_err_handle(OperandSize::S32, false, src, dst);
                    self.emit_ins(RISCVInstruction::remuw(OperandSize::S32, dst, src, dst));
                }
                ebpf::UREM64_REG if self.executable.get_sbpf_version().enable_pqr() => {
                    self.div_err_handle(OperandSize::S64, false, src, dst);
                    self.emit_ins(RISCVInstruction::remu(OperandSize::S64, dst, src, dst));
                }
                ebpf::SDIV32_REG if self.executable.get_sbpf_version().enable_pqr() => {
                    self.div_err_handle(OperandSize::S32, true, src, dst);
                    self.emit_ins(RISCVInstruction::divw(OperandSize::S32, dst, src, dst));
                    self.zero_extend(dst);
                }
                ebpf::SDIV64_REG if self.executable.get_sbpf_version().enable_pqr() => {
                    self.div_err_handle(OperandSize::S64, true, src, dst);
                    self.emit_ins(RISCVInstruction::div(OperandSize::S64, dst, src, dst));
                }
                ebpf::SREM32_REG if self.executable.get_sbpf_version().enable_pqr() => {
                    self.div_err_handle(OperandSize::S32, true, src, dst);
                    self.emit_ins(RISCVInstruction::remw(OperandSize::S32, dst, src, dst));
                    self.zero_extend(dst);
                }
                ebpf::SREM64_REG if self.executable.get_sbpf_version().enable_pqr() => {
                    self.div_err_handle(OperandSize::S64, true, src, dst);
                    self.emit_ins(RISCVInstruction::rem(OperandSize::S64, dst, src, dst));
                }
                
                // BPF_JMP32 class 
                // The upper 32 bits of both src and dst need to be cleared to zero.
                // Jump if Equal
                ebpf::JEQ32_IMM  if self.executable.get_sbpf_version().enable_jmp32()  => {
                    self.emit_validate_and_profile_instruction_count(Some(target_pc));
                    self.load_immediate(OperandSize::S64, T1, insn.imm as u32 as i64);
                    self.zero_extend(dst);
                    self.load_immediate(OperandSize::S64, REGISTER_SCRATCH, target_pc as i64);
                    let jump_offset = self.relative_to_target_pc(target_pc, 0);
                    self.emit_ins(RISCVInstruction::beq(OperandSize::S64, T1, dst, jump_offset as i64));
                    self.emit_undo_profile_instruction_count(target_pc);
                },
                ebpf::JEQ32_REG if self.executable.get_sbpf_version().enable_jmp32()   => {
                    self.emit_validate_and_profile_instruction_count(Some(target_pc));
                    self.zero_extend(src);
                    self.zero_extend(dst);
                    self.load_immediate(OperandSize::S64, REGISTER_SCRATCH, target_pc as i64);
                    let jump_offset = self.relative_to_target_pc(target_pc, 0);
                    self.emit_ins(RISCVInstruction::beq(OperandSize::S64, src, dst, jump_offset as i64));
                    self.emit_undo_profile_instruction_count(target_pc);
                }
                //Jump if Greater Than
                ebpf::JGT32_IMM if self.executable.get_sbpf_version().enable_jmp32()    => {
                    self.emit_validate_and_profile_instruction_count(Some(target_pc));
                    self.load_immediate(OperandSize::S64, T1, insn.imm as u32 as i64);
                    self.zero_extend(dst);
                    self.load_immediate(OperandSize::S64, REGISTER_SCRATCH, target_pc as i64);
                    let jump_offset = self.relative_to_target_pc(target_pc, 0);
                    self.emit_ins(RISCVInstruction::bltu(OperandSize::S64, T1, dst, jump_offset as i64));
                    self.emit_undo_profile_instruction_count(target_pc);
                },
                ebpf::JGT32_REG if self.executable.get_sbpf_version().enable_jmp32()    => {
                    self.emit_validate_and_profile_instruction_count(Some(target_pc));
                    self.zero_extend(src);
                    self.zero_extend(dst);
                    self.load_immediate(OperandSize::S64, REGISTER_SCRATCH, target_pc as i64);
                    let jump_offset = self.relative_to_target_pc(target_pc, 0);
                    self.emit_ins(RISCVInstruction::bltu(OperandSize::S64, src, dst, jump_offset as i64));
                    self.emit_undo_profile_instruction_count(target_pc);
                }
                //Jump if Greater or Equal
                ebpf::JGE32_IMM if self.executable.get_sbpf_version().enable_jmp32()    => { 
                    self.emit_validate_and_profile_instruction_count(Some(target_pc));
                    self.load_immediate(OperandSize::S64, T1, insn.imm as u32 as i64);
                    self.zero_extend(dst);
                    self.load_immediate(OperandSize::S64, REGISTER_SCRATCH, target_pc as i64);
                    let jump_offset = self.relative_to_target_pc(target_pc, 0);
                    self.emit_ins(RISCVInstruction::bgeu(OperandSize::S64, dst, T1, jump_offset as i64));
                    self.emit_undo_profile_instruction_count(target_pc);
                },
                ebpf::JGE32_REG if self.executable.get_sbpf_version().enable_jmp32()    => {
                    self.emit_validate_and_profile_instruction_count(Some(target_pc));
                    self.zero_extend(src);
                    self.zero_extend(dst);
                    self.load_immediate(OperandSize::S64, REGISTER_SCRATCH, target_pc as i64);
                    let jump_offset = self.relative_to_target_pc(target_pc, 0);
                    self.emit_ins(RISCVInstruction::bgeu(OperandSize::S64,dst, src,  jump_offset as i64));
                    self.emit_undo_profile_instruction_count(target_pc);
                }
                //Jump if less Than
                ebpf::JLT32_IMM if self.executable.get_sbpf_version().enable_jmp32()    => {
                    self.emit_validate_and_profile_instruction_count(Some(target_pc));
                    self.load_immediate(OperandSize::S64, T1, insn.imm as u32 as i64);
                    self.zero_extend(dst);
                    self.load_immediate(OperandSize::S64, REGISTER_SCRATCH, target_pc as i64);
                    let jump_offset = self.relative_to_target_pc(target_pc, 0);
                    self.emit_ins(RISCVInstruction::bltu(OperandSize::S64, dst,T1, jump_offset as i64));
                    self.emit_undo_profile_instruction_count(target_pc);
                },
                ebpf::JLT32_REG if self.executable.get_sbpf_version().enable_jmp32()    => {
                    self.emit_validate_and_profile_instruction_count(Some(target_pc));
                    self.zero_extend(src);
                    self.zero_extend(dst);
                    self.load_immediate(OperandSize::S64, REGISTER_SCRATCH, target_pc as i64);
                    let jump_offset = self.relative_to_target_pc(target_pc, 0);
                    self.emit_ins(RISCVInstruction::bltu(OperandSize::S64, dst, src, jump_offset as i64));
                    self.emit_undo_profile_instruction_count(target_pc);
                }
                //Jump if less or Equal
                ebpf::JLE32_IMM if self.executable.get_sbpf_version().enable_jmp32()    => {
                    self.emit_validate_and_profile_instruction_count(Some(target_pc));
                    self.load_immediate(OperandSize::S64, T1, insn.imm as u32 as i64);
                    self.zero_extend(dst);
                    self.load_immediate(OperandSize::S64, REGISTER_SCRATCH, target_pc as i64);
                    let jump_offset = self.relative_to_target_pc(target_pc, 0);
                    self.emit_ins(RISCVInstruction::bgeu(OperandSize::S64, T1,dst, jump_offset as i64));
                    self.emit_undo_profile_instruction_count(target_pc);
                },
                ebpf::JLE32_REG if self.executable.get_sbpf_version().enable_jmp32()    => {
                    self.emit_validate_and_profile_instruction_count(Some(target_pc));
                    self.zero_extend(src);
                    self.zero_extend(dst);
                    self.load_immediate(OperandSize::S64, REGISTER_SCRATCH, target_pc as i64);
                    let jump_offset = self.relative_to_target_pc(target_pc, 0);
                    self.emit_ins(RISCVInstruction::bgeu(OperandSize::S64, src, dst, jump_offset as i64));
                    self.emit_undo_profile_instruction_count(target_pc);
                },
                //Jump if Bitwise AND is Non-Zero
                ebpf::JSET32_IMM if self.executable.get_sbpf_version().enable_jmp32()   => {
                    self.emit_validate_and_profile_instruction_count(Some(target_pc));
                    self.load_immediate(OperandSize::S64, T1, insn.imm as u32 as i64);
                    self.zero_extend(dst);
                    self.load_immediate(OperandSize::S64, REGISTER_SCRATCH, target_pc as i64);
                    self.emit_ins(RISCVInstruction::and(OperandSize::S64, T1, dst, T1));
                    let jump_offset = self.relative_to_target_pc(target_pc, 0);
                    self.emit_ins(RISCVInstruction::bne(OperandSize::S64,T1, ZERO, jump_offset as i64));
                    self.emit_undo_profile_instruction_count(target_pc);
                },
                ebpf::JSET32_REG if self.executable.get_sbpf_version().enable_jmp32()   => {
                    self.emit_validate_and_profile_instruction_count(Some(target_pc));
                    self.zero_extend(src);
                    self.zero_extend(dst);
                    self.load_immediate(OperandSize::S64, REGISTER_SCRATCH, target_pc as i64);
                    self.emit_ins(RISCVInstruction::and(OperandSize::S64, src, dst, T1));
                    let jump_offset = self.relative_to_target_pc(target_pc, 0);
                    self.emit_ins(RISCVInstruction::bne(OperandSize::S64,T1, ZERO, jump_offset as i64));
                    self.emit_undo_profile_instruction_count(target_pc);
                },
                // Jump if Not Equal
                ebpf::JNE32_IMM if self.executable.get_sbpf_version().enable_jmp32()    => {
                    self.emit_validate_and_profile_instruction_count(Some(target_pc));
                    self.load_immediate(OperandSize::S64, T1, insn.imm as u32 as i64);
                    self.zero_extend(dst);
                    self.load_immediate(OperandSize::S64, REGISTER_SCRATCH, target_pc as i64);
                    let jump_offset = self.relative_to_target_pc(target_pc, 0);
                    self.emit_ins(RISCVInstruction::bne(OperandSize::S64,T1, dst, jump_offset as i64));
                    self.emit_undo_profile_instruction_count(target_pc);
                },
                ebpf::JNE32_REG if self.executable.get_sbpf_version().enable_jmp32()    => {
                    self.emit_validate_and_profile_instruction_count(Some(target_pc));
                    self.zero_extend(src);
                    self.zero_extend(dst);
                    self.load_immediate(OperandSize::S64, REGISTER_SCRATCH, target_pc as i64);
                    let jump_offset = self.relative_to_target_pc(target_pc, 0);
                    self.emit_ins(RISCVInstruction::bne(OperandSize::S64, src, dst, jump_offset as i64));
                    self.emit_undo_profile_instruction_count(target_pc);
                },
                
                //Jump if Greater Than Signed
                ebpf::JSGT32_IMM if self.executable.get_sbpf_version().enable_jmp32()   => {
                    self.emit_validate_and_profile_instruction_count(Some(target_pc));
                    self.load_immediate(OperandSize::S64, T1, insn.imm as i32 as i64);
                    self.emit_ins(RISCVInstruction::addiw(OperandSize::S64, dst, 0, dst)); // sign extend dst
                    self.load_immediate(OperandSize::S64, REGISTER_SCRATCH, target_pc as i64);
                    let jump_offset = self.relative_to_target_pc(target_pc, 0);
                    self.emit_ins(RISCVInstruction::blt(OperandSize::S64, T1, dst, jump_offset as i64));
                    self.emit_undo_profile_instruction_count(target_pc);
                },
                ebpf::JSGT32_REG if self.executable.get_sbpf_version().enable_jmp32()   => {
                    self.emit_validate_and_profile_instruction_count(Some(target_pc));
                    self.emit_ins(RISCVInstruction::addiw(OperandSize::S64, dst, 0, dst)); // sign extend dst
                    self.emit_ins(RISCVInstruction::addiw(OperandSize::S64, src, 0, src)); // sign extend src
                    self.load_immediate(OperandSize::S64, REGISTER_SCRATCH, target_pc as i64);
                    let jump_offset = self.relative_to_target_pc(target_pc, 0);
                    self.emit_ins(RISCVInstruction::blt(OperandSize::S64, src, dst, jump_offset as i64));
                    self.emit_undo_profile_instruction_count(target_pc);
                },
                //Jump if Greater or Equal Signed
                ebpf::JSGE32_IMM if self.executable.get_sbpf_version().enable_jmp32()   => {
                    self.emit_validate_and_profile_instruction_count(Some(target_pc));
                    self.load_immediate(OperandSize::S64, T1, insn.imm as i32 as i64);
                    self.emit_ins(RISCVInstruction::addiw(OperandSize::S64, dst, 0, dst)); // sign extend dst
                    self.load_immediate(OperandSize::S64, REGISTER_SCRATCH, target_pc as i64);
                    let jump_offset = self.relative_to_target_pc(target_pc, 0);
                    self.emit_ins(RISCVInstruction::bge(OperandSize::S64,dst, T1, jump_offset as i64));
                    self.emit_undo_profile_instruction_count(target_pc);
                },
                ebpf::JSGE32_REG if self.executable.get_sbpf_version().enable_jmp32()   => {
                    self.emit_validate_and_profile_instruction_count(Some(target_pc));
                    self.emit_ins(RISCVInstruction::addiw(OperandSize::S64, dst, 0, dst)); // sign extend dst
                    self.emit_ins(RISCVInstruction::addiw(OperandSize::S64, src, 0, src)); // sign extend src
                    self.load_immediate(OperandSize::S64, REGISTER_SCRATCH, target_pc as i64);
                    let jump_offset = self.relative_to_target_pc(target_pc, 0);
                    self.emit_ins(RISCVInstruction::bge(OperandSize::S64,dst, src,  jump_offset as i64));
                    self.emit_undo_profile_instruction_count(target_pc);
                },
                //Jump if less Than
                ebpf::JSLT32_IMM if self.executable.get_sbpf_version().enable_jmp32()    => {
                    self.emit_validate_and_profile_instruction_count(Some(target_pc));
                    self.load_immediate(OperandSize::S64, T1, insn.imm as i32 as i64);
                    self.emit_ins(RISCVInstruction::addiw(OperandSize::S64, dst, 0, dst)); // sign extend dst
                    self.load_immediate(OperandSize::S64, REGISTER_SCRATCH, target_pc as i64);
                    let jump_offset = self.relative_to_target_pc(target_pc, 0);
                    self.emit_ins(RISCVInstruction::blt(OperandSize::S64, dst,T1, jump_offset as i64));
                    self.emit_undo_profile_instruction_count(target_pc);
                },
                ebpf::JSLT32_REG if self.executable.get_sbpf_version().enable_jmp32()    => {
                    self.emit_validate_and_profile_instruction_count(Some(target_pc));
                    self.emit_ins(RISCVInstruction::addiw(OperandSize::S64, dst, 0, dst)); // sign extend dst
                    self.emit_ins(RISCVInstruction::addiw(OperandSize::S64, src, 0, src)); // sign extend src
                    self.load_immediate(OperandSize::S64, REGISTER_SCRATCH, target_pc as i64);
                    let jump_offset = self.relative_to_target_pc(target_pc, 0);
                    self.emit_ins(RISCVInstruction::blt(OperandSize::S64, dst, src, jump_offset as i64));
                    self.emit_undo_profile_instruction_count(target_pc);
                },
                //Jump if less or Equal Signed
                ebpf::JSLE32_IMM if self.executable.get_sbpf_version().enable_jmp32()    => {
                    self.emit_validate_and_profile_instruction_count(Some(target_pc));
                    self.load_immediate(OperandSize::S64, T1, insn.imm as i32 as i64);
                    self.emit_ins(RISCVInstruction::addiw(OperandSize::S64, dst, 0, dst)); // sign extend dst
                    self.load_immediate(OperandSize::S64, REGISTER_SCRATCH, target_pc as i64);
                    let jump_offset = self.relative_to_target_pc(target_pc, 0);
                    self.emit_ins(RISCVInstruction::bge(OperandSize::S64, T1,dst, jump_offset as i64));
                    self.emit_undo_profile_instruction_count(target_pc);
                },
                ebpf::JSLE32_REG if self.executable.get_sbpf_version().enable_jmp32()    => {
                    self.emit_validate_and_profile_instruction_count(Some(target_pc));
                    self.emit_ins(RISCVInstruction::addiw(OperandSize::S64, dst, 0, dst)); // sign extend dst
                    self.emit_ins(RISCVInstruction::addiw(OperandSize::S64, src, 0, src)); // sign extend src
                    self.load_immediate(OperandSize::S64, REGISTER_SCRATCH, target_pc as i64);
                    let jump_offset = self.relative_to_target_pc(target_pc, 0);
                    self.emit_ins(RISCVInstruction::bge(OperandSize::S64, src, dst, jump_offset as i64));
                    self.emit_undo_profile_instruction_count(target_pc);
                },

                ebpf::JA         => {
                    self.emit_validate_and_profile_instruction_count(Some(target_pc));
                    self.load_immediate(OperandSize::S64, REGISTER_SCRATCH, target_pc as i64);
                    let jump_offset = self.relative_to_target_pc(target_pc, 0);
                    self.emit_ins(RISCVInstruction::jal(jump_offset as i64, ZERO));
                },
                // Jump if Equal
                ebpf::JEQ64_IMM   => {
                    self.emit_validate_and_profile_instruction_count(Some(target_pc));
                    self.load_immediate(OperandSize::S64, T1, insn.imm);
                    self.load_immediate(OperandSize::S64, REGISTER_SCRATCH, target_pc as i64);
                    let jump_offset = self.relative_to_target_pc(target_pc, 0);
                    self.emit_ins(RISCVInstruction::beq(OperandSize::S64,T1, dst, jump_offset as i64));
                    self.emit_undo_profile_instruction_count(target_pc);
                },
                ebpf::JEQ64_REG   => {
                    self.emit_validate_and_profile_instruction_count(Some(target_pc));
                    self.load_immediate(OperandSize::S64, REGISTER_SCRATCH, target_pc as i64);
                    let jump_offset = self.relative_to_target_pc(target_pc, 0);
                    self.emit_ins(RISCVInstruction::beq(OperandSize::S64, src,dst,  jump_offset as i64));
                    self.emit_undo_profile_instruction_count(target_pc);
                }
                //Jump if Greater Than
                ebpf::JGT64_IMM    => {
                    self.emit_validate_and_profile_instruction_count(Some(target_pc));
                    self.load_immediate(OperandSize::S64, T1, insn.imm);
                    self.load_immediate(OperandSize::S64, REGISTER_SCRATCH, target_pc as i64);
                    let jump_offset = self.relative_to_target_pc(target_pc, 0);
                    self.emit_ins(RISCVInstruction::bltu(OperandSize::S64, T1,dst, jump_offset as i64));
                    self.emit_undo_profile_instruction_count(target_pc);
                },
                ebpf::JGT64_REG    => {
                    self.emit_validate_and_profile_instruction_count(Some(target_pc));
                    self.load_immediate(OperandSize::S64, REGISTER_SCRATCH, target_pc as i64);
                    let jump_offset = self.relative_to_target_pc(target_pc, 0);
                    self.emit_ins(RISCVInstruction::bltu(OperandSize::S64, src,dst,  jump_offset as i64));
                    self.emit_undo_profile_instruction_count(target_pc);
                }
                //Jump if Greater or Equal
                ebpf::JGE64_IMM    => {
                    self.emit_validate_and_profile_instruction_count(Some(target_pc));
                    self.load_immediate(OperandSize::S64, T1, insn.imm);
                    self.load_immediate(OperandSize::S64, REGISTER_SCRATCH, target_pc as i64);
                    let jump_offset = self.relative_to_target_pc(target_pc, 0);
                    self.emit_ins(RISCVInstruction::bgeu(OperandSize::S64,dst, T1, jump_offset as i64));
                    self.emit_undo_profile_instruction_count(target_pc);
                },
                ebpf::JGE64_REG    => {
                    self.emit_validate_and_profile_instruction_count(Some(target_pc));
                    self.load_immediate(OperandSize::S64, REGISTER_SCRATCH, target_pc as i64);
                    let jump_offset = self.relative_to_target_pc(target_pc, 0);
                    self.emit_ins(RISCVInstruction::bgeu(OperandSize::S64,dst, src,  jump_offset as i64));
                    self.emit_undo_profile_instruction_count(target_pc);
                }
                //Jump if less Than
                ebpf::JLT64_IMM    => {
                    self.emit_validate_and_profile_instruction_count(Some(target_pc));
                    self.load_immediate(OperandSize::S64, T1, insn.imm);
                    self.load_immediate(OperandSize::S64, REGISTER_SCRATCH, target_pc as i64);
                    let jump_offset = self.relative_to_target_pc(target_pc, 0);
                    self.emit_ins(RISCVInstruction::bltu(OperandSize::S64, dst,T1, jump_offset as i64));
                    self.emit_undo_profile_instruction_count(target_pc);
                },
                ebpf::JLT64_REG    => {
                    self.emit_validate_and_profile_instruction_count(Some(target_pc));
                    self.load_immediate(OperandSize::S64, REGISTER_SCRATCH, target_pc as i64);
                    let jump_offset = self.relative_to_target_pc(target_pc, 0);
                    self.emit_ins(RISCVInstruction::bltu(OperandSize::S64, dst, src, jump_offset as i64));
                    self.emit_undo_profile_instruction_count(target_pc);
                }
                //Jump if less or Equal
                ebpf::JLE64_IMM    => {
                    self.emit_validate_and_profile_instruction_count(Some(target_pc));
                    self.load_immediate(OperandSize::S64, T1, insn.imm);
                    self.load_immediate(OperandSize::S64, REGISTER_SCRATCH, target_pc as i64);
                    let jump_offset = self.relative_to_target_pc(target_pc, 0);
                    self.emit_ins(RISCVInstruction::bgeu(OperandSize::S64, T1,dst, jump_offset as i64));
                    self.emit_undo_profile_instruction_count(target_pc);
                },
                ebpf::JLE64_REG    => {
                    self.emit_validate_and_profile_instruction_count(Some(target_pc));
                    self.load_immediate(OperandSize::S64, REGISTER_SCRATCH, target_pc as i64);
                    let jump_offset = self.relative_to_target_pc(target_pc, 0);
                    self.emit_ins(RISCVInstruction::bgeu(OperandSize::S64, src, dst, jump_offset as i64));
                    self.emit_undo_profile_instruction_count(target_pc);
                },
                //Jump if Bitwise AND is Non-Zero
                ebpf::JSET64_IMM   => {
                    self.emit_validate_and_profile_instruction_count(Some(target_pc));
                    self.load_immediate(OperandSize::S64, T1, insn.imm);
                    self.load_immediate(OperandSize::S64, REGISTER_SCRATCH, target_pc as i64);
                    self.emit_ins(RISCVInstruction::and(OperandSize::S64, T1, dst, T1));
                    let jump_offset = self.relative_to_target_pc(target_pc, 0);
                    self.emit_ins(RISCVInstruction::bne(OperandSize::S64,T1, ZERO, jump_offset as i64));
                    self.emit_undo_profile_instruction_count(target_pc);
                },
                ebpf::JSET64_REG   => {
                    self.emit_validate_and_profile_instruction_count(Some(target_pc));
                    self.load_immediate(OperandSize::S64, REGISTER_SCRATCH, target_pc as i64);
                    self.emit_ins(RISCVInstruction::and(OperandSize::S64, src, dst, T1));
                    let jump_offset = self.relative_to_target_pc(target_pc, 0);
                    self.emit_ins(RISCVInstruction::bne(OperandSize::S64,T1, ZERO, jump_offset as i64));
                    self.emit_undo_profile_instruction_count(target_pc);
                },
                // Jump if Not Equal
                ebpf::JNE64_IMM    => {
                    self.emit_validate_and_profile_instruction_count(Some(target_pc));
                    self.load_immediate(OperandSize::S64, T1, insn.imm);
                    self.load_immediate(OperandSize::S64, REGISTER_SCRATCH, target_pc as i64);
                    let jump_offset = self.relative_to_target_pc(target_pc, 0);
                    self.emit_ins(RISCVInstruction::bne(OperandSize::S64,T1, dst, jump_offset as i64));
                    self.emit_undo_profile_instruction_count(target_pc);
                },
                ebpf::JNE64_REG    => {
                    self.emit_validate_and_profile_instruction_count(Some(target_pc));
                    self.load_immediate(OperandSize::S64, REGISTER_SCRATCH, target_pc as i64);
                    let jump_offset = self.relative_to_target_pc(target_pc, 0);
                    self.emit_ins(RISCVInstruction::bne(OperandSize::S64, src,dst,  jump_offset as i64));
                    self.emit_undo_profile_instruction_count(target_pc);
                },
                
                //Jump if Greater Than Signed
                ebpf::JSGT64_IMM   => {
                    self.emit_validate_and_profile_instruction_count(Some(target_pc));
                    self.load_immediate(OperandSize::S64, T1, insn.imm);
                    self.load_immediate(OperandSize::S64, REGISTER_SCRATCH, target_pc as i64);
                    let jump_offset = self.relative_to_target_pc(target_pc, 0);
                    self.emit_ins(RISCVInstruction::blt(OperandSize::S64, T1,dst, jump_offset as i64));
                    self.emit_undo_profile_instruction_count(target_pc);
                },
                ebpf::JSGT64_REG   => {
                    self.emit_validate_and_profile_instruction_count(Some(target_pc));
                    self.load_immediate(OperandSize::S64, REGISTER_SCRATCH, target_pc as i64);
                    let jump_offset = self.relative_to_target_pc(target_pc, 0);
                    self.emit_ins(RISCVInstruction::blt(OperandSize::S64, src,dst,  jump_offset as i64));
                    self.emit_undo_profile_instruction_count(target_pc);
                },
                //Jump if Greater or Equal Signed
                ebpf::JSGE64_IMM   => {
                    self.emit_validate_and_profile_instruction_count(Some(target_pc));
                    self.load_immediate(OperandSize::S64, T1, insn.imm);
                    self.load_immediate(OperandSize::S64, REGISTER_SCRATCH, target_pc as i64);
                    let jump_offset = self.relative_to_target_pc(target_pc, 0);
                    self.emit_ins(RISCVInstruction::bge(OperandSize::S64,dst, T1, jump_offset as i64));
                    self.emit_undo_profile_instruction_count(target_pc);
                },
                ebpf::JSGE64_REG   => {
                    self.emit_validate_and_profile_instruction_count(Some(target_pc));
                    self.load_immediate(OperandSize::S64, REGISTER_SCRATCH, target_pc as i64);
                    let jump_offset = self.relative_to_target_pc(target_pc, 0);
                    self.emit_ins(RISCVInstruction::bge(OperandSize::S64,dst, src,  jump_offset as i64));
                    self.emit_undo_profile_instruction_count(target_pc);
                },
                //Jump if less Than
                ebpf::JSLT64_IMM    => {
                    self.emit_validate_and_profile_instruction_count(Some(target_pc));
                    self.load_immediate(OperandSize::S64, T1, insn.imm);
                    self.load_immediate(OperandSize::S64, REGISTER_SCRATCH, target_pc as i64);
                    let jump_offset = self.relative_to_target_pc(target_pc, 0);
                    self.emit_ins(RISCVInstruction::blt(OperandSize::S64, dst,T1, jump_offset as i64));
                    self.emit_undo_profile_instruction_count(target_pc);
                },
                ebpf::JSLT64_REG    => {
                    self.emit_validate_and_profile_instruction_count(Some(target_pc));
                    self.load_immediate(OperandSize::S64, REGISTER_SCRATCH, target_pc as i64);
                    let jump_offset = self.relative_to_target_pc(target_pc, 0);
                    self.emit_ins(RISCVInstruction::blt(OperandSize::S64, dst, src, jump_offset as i64));
                    self.emit_undo_profile_instruction_count(target_pc);
                },
                //Jump if less or Equal Signed
                ebpf::JSLE64_IMM    => {
                    self.emit_validate_and_profile_instruction_count(Some(target_pc));
                    self.load_immediate(OperandSize::S64, T1, insn.imm);
                    self.load_immediate(OperandSize::S64, REGISTER_SCRATCH, target_pc as i64);
                    let jump_offset = self.relative_to_target_pc(target_pc, 0);
                    self.emit_ins(RISCVInstruction::bge(OperandSize::S64, T1,dst, jump_offset as i64));
                    self.emit_undo_profile_instruction_count(target_pc);
                },
                ebpf::JSLE64_REG    => {
                    self.emit_validate_and_profile_instruction_count(Some(target_pc));
                    self.load_immediate(OperandSize::S64, REGISTER_SCRATCH, target_pc as i64);
                    let jump_offset = self.relative_to_target_pc(target_pc, 0);
                    self.emit_ins(RISCVInstruction::bge(OperandSize::S64, src, dst, jump_offset as i64));
                    self.emit_undo_profile_instruction_count(target_pc);
                },
                ebpf::CALL_IMM   => {
                    // For JIT, external functions MUST be registered at compile time.
                    let mut resolved = false;

                    // External syscall
                    if !self.executable.get_sbpf_version().static_syscalls() || insn.src == 0 {
                        if let Some((_, function)) =
                                self.executable.get_loader().get_function_registry().lookup_by_key(insn.imm as u32) {
                            self.emit_validate_and_profile_instruction_count(Some(0));
                            self.load_immediate(OperandSize::S64, REGISTER_SCRATCH, function as usize as i64);
                            self.emit_ins(RISCVInstruction::addi(OperandSize::S64, SP, -8, SP));
                            self.store(OperandSize::S64, SP, RA, 0);
                            self.emit_ins(RISCVInstruction::jal(self.relative_to_anchor(ANCHOR_EXTERNAL_FUNCTION_CALL, 0), RA));
                            self.load(OperandSize::S64, SP, 0, RA);
                            self.emit_ins(RISCVInstruction::addi(OperandSize::S64, SP, 8, SP));
                            self.emit_undo_profile_instruction_count(0);
                            resolved = true;
                        }
                    }
                    // Internal call
                    if self.executable.get_sbpf_version().static_syscalls() {
                        let target_pc = (self.pc as i64).saturating_add(insn.imm).saturating_add(1);
                        if ebpf::is_pc_in_program(self.program, target_pc as usize) && insn.src == 1 {
                            self.emit_internal_call(Value::Constant64(target_pc as i64, true));
                            resolved = true;
                        }
                    } else if let Some((_function_name, target_pc)) =
                        self.executable
                            .get_function_registry()
                            .lookup_by_key(insn.imm as u32) {
                        self.emit_internal_call(Value::Constant64(target_pc as i64, true));
                        resolved = true;
                    }
                    if !resolved {
                        self.load_immediate(OperandSize::S64, REGISTER_SCRATCH, self.pc as i64);
                        self.emit_ins(RISCVInstruction::jal(self.relative_to_anchor(ANCHOR_CALL_UNSUPPORTED_INSTRUCTION, 0), ZERO));
                    }
                },
                ebpf::CALL_REG  => {
                    let target_pc = if self.executable.get_sbpf_version().callx_uses_src_reg() {
                        src
                    } else if self.executable.get_sbpf_version().callx_uses_dst_reg() {
                        dst
                    } else {
                        REGISTER_MAP[insn.imm as usize]
                    };
                    self.emit_internal_call(Value::Register(target_pc));
                },

                ebpf::EXIT      =>{
                    self.emit_validate_and_profile_instruction_count(Some(0));
                    
                    let call_depth_access=self.slot_in_vm(RuntimeEnvironmentSlot::CallDepth) as i64;
                    self.load(OperandSize::S64, REGISTER_PTR_TO_VM, call_depth_access, T5);
                
                    // If CallDepth == 0, we've reached the exit instruction of the entry point
                    let instruction_end = unsafe { self.result.text_section.as_ptr().add(self.offset_in_text_section) }; 

                    self.emit_ins(RISCVInstruction::bne(OperandSize::S64, T5, ZERO, 8)); // if call_depth != 0, jump over next instruction
                    self.emit_ins(RISCVInstruction::jal(self.relative_to_anchor(ANCHOR_EXIT, 0), ZERO)); // jump to exit
                    // we're done

                    // else decrement and update CallDepth
                    self.emit_ins(RISCVInstruction::addi(OperandSize::S64, T5, -1, T5)); // env.call_depth -= 1;
                    self.store(OperandSize::S64, REGISTER_PTR_TO_VM, T5, call_depth_access);

                    // and return
                    self.emit_ins(RISCVInstruction::return_near());
                }
                _ => return Err(EbpfError::UnsupportedInstruction),
            }
            self.pc += 1;
        }
        // Bumper in case there was no final exit 
        if self.offset_in_text_section + MAX_MACHINE_CODE_LENGTH_PER_INSTRUCTION * 2 >= self.result.text_section.len() {
            return Err(EbpfError::ExhaustedTextSegment(self.pc));
        }   
        self.emit_validate_and_profile_instruction_count(Some(self.pc + 1));
        self.load_immediate(OperandSize::S64, REGISTER_SCRATCH, self.pc as i64); // Save pc
        self.emit_set_exception_kind(EbpfError::ExecutionOverrun);
        self.emit_ins(RISCVInstruction::jal(self.relative_to_anchor(ANCHOR_THROW_EXCEPTION, 0), ZERO));

        self.resolve_jumps();
        self.result.seal(self.offset_in_text_section)?;
        Ok(self.result)
    }

    fn emit_validate_and_profile_instruction_count(&mut self, target_pc: Option<usize>) {
        self.emit_validate_instruction_count(Some(self.pc));
        self.emit_profile_instruction_count(target_pc);
    }

    // This function helps the optimizer to inline the machinecode emission while avoiding stack allocations
    #[inline(always)]
    pub fn emit_ins(&mut self,instruction: RISCVInstruction) {
        self.emit(instruction.emit());
        self.result.machine_instruction_count += 1;
    }

    /// Determine the offset and execute the load instruction
    pub fn load(&mut self,size: OperandSize,source1: u8,offset:i64,destination: u8){
        if offset >= -2048 && offset <= 2047 {
            // offset in 12-bit range, use ld
            self.emit_ins(RISCVInstruction::load(size, source1, offset, destination));
        } else {
            self.load_immediate(size, T1, offset);
            self.emit_ins(RISCVInstruction::add(size, source1, T1, T1));
            self.emit_ins(RISCVInstruction::load(size, T1, 0, destination));
        }
    }

    /// Determine the offset and execute the store instruction
    pub fn store(&mut self, size: OperandSize, source1: u8, source2: u8, offset:i64){
        if offset >= -2048 && offset <= 2047 {
            // offset in 12-bit range, use sd
            self.emit_ins(RISCVInstruction::store(size, source1, source2, offset));
        } else {
            self.load_immediate(size, T1, offset);
            self.emit_ins(RISCVInstruction::add(size, source1, T1, T1));
            self.emit_ins(RISCVInstruction::store(size, T1, source2, 0));
        }
    }

    /// clear the high 32 bits of a 64-bit register
    pub fn zero_extend(&mut self,destination: u8) {
        self.emit_ins(RISCVInstruction::slli(OperandSize::S64, destination, 32, destination));
        self.emit_ins(RISCVInstruction::srli(OperandSize::S64, destination, 32, destination));
    }

    /// Divide the immediate number into the high 20 bits and the low 12 bits
    fn load_immediate_with_lui_and_addi(&mut self, size: OperandSize, destination: u8, immediate: i64) {
        if immediate >= -2048 && immediate <= 2047 {
            // imm in 12-bit range, use ADDI directly
            self.emit_ins(RISCVInstruction::addi(size, 0, immediate, destination));
        } else {
            // handel immediate number larger than 12 bits
            let upper_imm = immediate >> 12; // high 20 bits
            let lower_imm = immediate & 0xFFF; // low 12 bits
            let sign_ext = if lower_imm & 0x800 != 0 { 1 } else { 0 };

            // Step 1: load high 20 bits using LUI
            self.emit_ins(RISCVInstruction::lui(
                size,
                upper_imm + sign_ext, 
                destination,
            ));

            // Step 2: add low 12 bits using ADDI
            if lower_imm != 0 {
                self.emit_ins(RISCVInstruction::addi(
                    size,
                    destination,
                    lower_imm,
                    destination,
                ));
            }
        }
    }

    /// Load immediate (LI rd, imm)
    #[inline]
    pub fn load_immediate(&mut self, size: OperandSize, destination: u8, immediate: i64) {
        if immediate >= i32::MIN as i64 && immediate <= i32::MAX as i64 {
            self.load_immediate_with_lui_and_addi(size, destination, immediate);
        } else {
            let upper_imm = immediate >> 32; // high 32 bits
            let lower_imm = immediate & 0xFFFFFFFF; // low 32 bits

            // Step 1: handle high 32 bits immediate to destination register
            self.load_immediate_with_lui_and_addi(size, destination, upper_imm);

            // Step 2: use SLLI to shift left by 32 bits
            self.emit_ins(RISCVInstruction::slli(size, destination, 32, destination));

            // Step 3: handle low 32 bits immediate
            self.load_immediate_with_lui_and_addi(size, T0, lower_imm);
            self.zero_extend(T0);

            // Step 4: use OR to combine high and low parts
            self.emit_ins(RISCVInstruction::or(size, destination, T0, destination));
        }
    }

    #[inline]
    pub fn rotate_right(&mut self,size: OperandSize, source1: u8, shamt: i64, destination: u8) {
        self.emit_ins(RISCVInstruction::mov(size, source1, T2));
        self.emit_ins(RISCVInstruction::mov(size, source1, T3));
        self.emit_ins(RISCVInstruction::slli(size, T2, shamt, T2));
        self.emit_ins(RISCVInstruction::srli(size, T3, shamt, T3));
        self.emit_ins(RISCVInstruction::or(size, T2, T3, destination));
    }

    #[inline]
    pub fn should_sanitize_constant(&mut self,value: i64) -> bool {
        if !self.config.sanitize_user_provided_values {
            return false;
        }

        match value as u64 {
            0xFFFF | 0xFFFFFF | 0xFFFFFFFF | 0xFFFFFFFFFF | 0xFFFFFFFFFFFF | 0xFFFFFFFFFFFFFF
            | 0xFFFFFFFFFFFFFFFF => false,
            v if v <= 0xFF => false,
            v if !v <= 0xFF => false,
            _ => true,
        }
    }

    #[inline]
    fn slot_in_vm(&self, slot: RuntimeEnvironmentSlot) -> i32 {
        8 * (slot as i32 - self.runtime_environment_key)
    }

    #[inline]
    pub(crate) fn emit<T: std::fmt::Debug>(&mut self, data: T) {
        unsafe {
            let ptr = self.result.text_section.as_ptr().add(self.offset_in_text_section);
            #[allow(clippy::cast_ptr_alignment)]
            ptr::write_unaligned(ptr as *mut T, data as T);
        }
        self.offset_in_text_section += mem::size_of::<T>();
    }

    #[inline]
    pub fn emit_sanitized_load_immediate(&mut self, destination: u8, value: i64) {
        let lower_key = self.immediate_value_key as i32 as i64;
        if value >= i32::MIN as i64 && value <= i32::MAX as i64 {
            self.load_immediate(OperandSize::S64, destination, value.wrapping_sub(lower_key));
            self.load_immediate(OperandSize::S64, T1, lower_key); // wrapping_add(lower_key)
            self.emit_ins(RISCVInstruction::add(OperandSize::S64, destination, T1, destination));
        } else if value as u64 & u32::MAX as u64 == 0 {
            self.load_immediate(OperandSize::S64, destination, value.rotate_right(32).wrapping_sub(lower_key));
            self.load_immediate(OperandSize::S64, T1, lower_key);
            self.emit_ins(RISCVInstruction::add(OperandSize::S64, destination, T1, destination)); // wrapping_add(key)
            self.emit_ins(RISCVInstruction::slli(OperandSize::S64, destination, 32, destination)); // shift_left(32)
        } else if destination != REGISTER_SCRATCH {
            self.load_immediate(OperandSize::S64, destination, value.wrapping_sub(self.immediate_value_key));
            self.load_immediate(OperandSize::S64, REGISTER_SCRATCH, self.immediate_value_key);
            self.emit_ins(RISCVInstruction::add(OperandSize::S64, destination, REGISTER_SCRATCH, destination)); // wrapping_add(immediate_value_key)
        } else {
            let upper_key = (self.immediate_value_key >> 32) as i32 as i64;
            self.load_immediate(OperandSize::S64, destination, value.wrapping_sub(lower_key).rotate_right(32).wrapping_sub(upper_key));
            self.load_immediate(OperandSize::S64, T1, upper_key); // wrapping_add(upper_key)
            self.emit_ins(RISCVInstruction::add(OperandSize::S64, destination, T1, destination));
            self.rotate_right(OperandSize::S64, destination, 32, destination);
            self.load_immediate(OperandSize::S64, T1, lower_key); // wrapping_add(lower_key)
            self.emit_ins(RISCVInstruction::add(OperandSize::S64, destination, T1, destination));
        } 
    }

    #[inline]
    pub fn emit_sanitized_add(&mut self, size: OperandSize, destination: u8, immediate: i64) {
        if self.should_sanitize_constant(immediate) {
            self.emit_sanitized_load_immediate(T4, immediate);
            if size == OperandSize::S32 {
                self.emit_ins(RISCVInstruction::addw(size, T4, destination, destination));
            } else {
                self.emit_ins(RISCVInstruction::add(size, T4, destination, destination));
            }
        } else {
            self.load_immediate(size, T1, immediate);
            if size == OperandSize::S32 {
                self.emit_ins(RISCVInstruction::addw(size, T1, destination, destination));
            } else {
                self.emit_ins(RISCVInstruction::add(size, T1, destination, destination));
            }
        }
    }

    #[inline]
    pub fn emit_sanitized_sub(&mut self,size: OperandSize, destination: u8, immediate: i64) {
        if self.should_sanitize_constant(immediate) {
            self.emit_sanitized_load_immediate(T4, immediate);
            if size == OperandSize::S32 {
                self.emit_ins(RISCVInstruction::subw(size, destination, T4, destination));
            } else {
                self.emit_ins(RISCVInstruction::sub(size, destination, T4, destination));
            }
        } else {
            self.load_immediate(size, T1, immediate);
            if size == OperandSize::S32 {
                self.emit_ins(RISCVInstruction::subw(size, destination, T1, destination));
            } else {
                self.emit_ins(RISCVInstruction::sub(size, destination, T1, destination));
            }
        }
    }

    #[inline]
    pub fn emit_sanitized_or(&mut self,size: OperandSize, destination: u8, immediate: i64) {
        if self.should_sanitize_constant(immediate) {
            self.emit_sanitized_load_immediate(T4, immediate);
            self.emit_ins(RISCVInstruction::or(size, destination, T4, destination));
        } else if immediate >= -2048 && immediate <= 2047 {
            // 立即数在 12 位范围内，直接使用 ORI
            self.emit_ins(RISCVInstruction::ori(
                size,
                destination,
                immediate,
                destination,
            ));
        } else {
            self.load_immediate(size, T1, immediate);
            self.emit_ins(RISCVInstruction::or(size, destination, T1, destination));
        }
    }

    #[inline]
    pub fn emit_sanitized_xor(&mut self,size: OperandSize, destination: u8, immediate: i64) {
        if self.should_sanitize_constant(immediate) {
            self.emit_sanitized_load_immediate(T4, immediate);
            self.emit_ins(RISCVInstruction::xor(size, destination, T4, destination));
        } else if immediate >= -2048 && immediate <= 2047 {
            self.emit_ins(RISCVInstruction::xori(
                size,
                destination,
                immediate,
                destination,
            ));
        } else {
            self.load_immediate(size, T1, immediate);
            self.emit_ins(RISCVInstruction::xor(size, destination, T1, destination));
        }
    }

    #[inline]
    pub fn emit_sanitized_and(&mut self,size: OperandSize, destination: u8, immediate: i64) {
        if self.should_sanitize_constant(immediate) {
            self.emit_sanitized_load_immediate(T4, immediate);
            self.emit_ins(RISCVInstruction::and(size, destination, T4, destination));
        } else if immediate >= -2048 && immediate <= 2047 {
            self.emit_ins(RISCVInstruction::andi(
                size,
                destination,
                immediate,
                destination,
            ));
        } else {
            self.load_immediate(size, T1, immediate);
            self.emit_ins(RISCVInstruction::and(size, destination, T1, destination));
        }
    }   

    fn emit_validate_instruction_count(&mut self, pc: Option<usize>) {
        if !self.config.enable_instruction_meter {
            return;
        }
        // Update `MACHINE_CODE_PER_INSTRUCTION_METER_CHECKPOINT` if you change the code generation here
        if let Some(pc) = pc {
            self.last_instruction_meter_validation_pc = pc;
            self.emit_sanitized_load_immediate(REGISTER_SCRATCH, pc as i64);
        }
        // If instruction_meter >= pc, throw ExceededMaxInstructions
        self.emit_ins(RISCVInstruction::bgeu(OperandSize::S64, REGISTER_SCRATCH, REGISTER_INSTRUCTION_METER, self.relative_to_anchor(ANCHOR_THROW_EXCEEDED_MAX_INSTRUCTIONS, 0)));
        
    }

    fn emit_profile_instruction_count(&mut self, target_pc: Option<usize>) {
        if !self.config.enable_instruction_meter {
            return;
        }
        match target_pc {
            Some(target_pc) => {
                let immediate = target_pc as i64 - self.pc as i64 - 1;
                self.emit_sanitized_add(OperandSize::S64, REGISTER_INSTRUCTION_METER, immediate); // instruction_meter += target_pc - (self.pc + 1);
            },
            None => {
                self.emit_ins(RISCVInstruction::add(OperandSize::S64, REGISTER_SCRATCH, REGISTER_INSTRUCTION_METER, REGISTER_INSTRUCTION_METER)); // instruction_meter += target_pc;
                let immediate = -(self.pc as i64 + 1);
                self.load_immediate(OperandSize::S64, T1, immediate);
                self.emit_ins(RISCVInstruction::add(OperandSize::S64, REGISTER_INSTRUCTION_METER, T1, REGISTER_INSTRUCTION_METER)); // instruction_meter -= self.pc + 1;
            }
        }
    }

    fn emit_undo_profile_instruction_count(&mut self, target_pc: usize) {
        if self.config.enable_instruction_meter {
            let immediate = self.pc as i64 + 1 - target_pc as i64;
            self.emit_sanitized_add(OperandSize::S64, REGISTER_INSTRUCTION_METER, immediate); // instruction_meter += (self.pc + 1) - target_pc;
        }
    }

    #[inline]
    fn div_err_handle(&mut self, size: OperandSize, signed: bool, src: u8, dst: u8){
        self.emit_ins(RISCVInstruction::mov(OperandSize::S64, src, T6));
        if size == OperandSize::S32 {
            self.zero_extend(T6);
        }

        // Prevent division by zero
        self.load_immediate(OperandSize::S64, REGISTER_SCRATCH, self.pc as i64);// Save pc
        self.emit_ins(RISCVInstruction::beq(OperandSize::S64, T6, ZERO, self.relative_to_anchor(ANCHOR_DIV_BY_ZERO, 0)));

        // Signed division overflows with MIN / -1.
        // If we have an immediate and it's not -1, we can skip the following check.
        if signed  == true {
            self.load_immediate(size, T4, if let OperandSize::S64 = size { i64::MIN } else { i32::MIN as u32 as i64 });
            self.emit_ins(RISCVInstruction::sltu(OperandSize::S64, dst, T4, T4));// if (dst < T4) ? 1 : 0 只有dst等于最小值时，结果为0
            self.emit_ins(RISCVInstruction::sltiu(OperandSize::S64, T4, 1, T4));// if (T4 < 1) ? 1 : 0

            // The exception case is: dst == MIN && src == -1
            // Via De Morgan's law becomes: !(dst != MIN || src != -1)
            // Also, we know that src != 0 in here, so we can use it to set REGISTER_SCRATCH to something not zero
            self.emit_ins(RISCVInstruction::addi(OperandSize::S64, src, 1, T5));
            self.emit_ins(RISCVInstruction::sltiu(OperandSize::S64, T5, 1, T5));

            // MIN / -1, raise EbpfError::DivideOverflow
            self.emit_ins(RISCVInstruction::and(OperandSize::S64, T5, T4, T5));
            self.load_immediate(OperandSize::S64, REGISTER_SCRATCH, self.pc as i64);
            self.emit_ins(RISCVInstruction::bne(OperandSize::S64, T5, ZERO, self.relative_to_anchor(ANCHOR_DIV_OVERFLOW, 0)));
        }
    }

    fn emit_set_exception_kind(&mut self, err: EbpfError) {
        let err_kind = unsafe { *std::ptr::addr_of!(err).cast::<u64>() };
        let err_discriminant = ProgramResult::Err(err).discriminant();
        self.load_immediate(OperandSize::S64, T1, self.slot_in_vm(RuntimeEnvironmentSlot::ProgramResult) as i64);
        self.emit_ins(RISCVInstruction::add(OperandSize::S64, REGISTER_PTR_TO_VM, T1, REGISTER_MAP[0]));
        // result.discriminant = err_discriminant;
        self.load_immediate(OperandSize::S64, T1, err_discriminant as i64);
        self.store(OperandSize::S64, REGISTER_MAP[0], T1, 0);
        // err.kind = err_kind;
        self.load_immediate(OperandSize::S64, T1, err_kind as i64);
        self.store(OperandSize::S64, REGISTER_MAP[0], T1, std::mem::size_of::<u64>() as i64);
    }

    #[inline]
    fn emit_address_translation(&mut self, dst: Option<u8>, vm_addr: Value, len: u64, value: Option<Value>) {
        debug_assert_ne!(dst.is_some(), value.is_some());

        let stack_slot_of_value_to_store = -96; 
        match value {
            Some(Value::Register(reg)) => {
                self.store(OperandSize::S64, SP, reg, stack_slot_of_value_to_store);
            }
            Some(Value::Constant64(constant, user_provided)) => {
                debug_assert!(user_provided);
                // First half of emit_sanitized_load_immediate(stack_slot_of_value_to_store, constant)
                let lower_key = self.immediate_value_key as i32 as i64;
                self.load_immediate(OperandSize::S64, REGISTER_SCRATCH, constant.wrapping_sub(lower_key));
                self.store(OperandSize::S64, SP, REGISTER_SCRATCH, stack_slot_of_value_to_store);
            }
            _ => {}
        }

        match vm_addr {
            Value::RegisterPlusConstant64(reg, constant, user_provided) => {
                if user_provided && self.should_sanitize_constant(constant) {
                    self.emit_sanitized_load_immediate(REGISTER_SCRATCH, constant);
                } else {
                    self.load_immediate(OperandSize::S64, REGISTER_SCRATCH, constant);
                }
                self.emit_ins(RISCVInstruction::add(OperandSize::S64, reg, REGISTER_SCRATCH, REGISTER_SCRATCH));
            },
            _ => {
                #[cfg(debug_assertions)]
                unreachable!();
            },
        }
        if self.config.enable_address_translation {
            self.emit_ins(RISCVInstruction::addi(OperandSize::S64, SP, -8, SP));
            self.store(OperandSize::S64, SP, RA, 0);
            let anchor_base = match value {
                Some(Value::Register(_reg)) => 4,
                Some(Value::Constant64(_constant, _user_provided)) => 8,
                _ => 0,
            };
            let anchor = ANCHOR_TRANSLATE_MEMORY_ADDRESS + anchor_base + len.trailing_zeros() as usize;
            self.load_immediate(OperandSize::S64, T1, self.pc as i64);
            self.emit_ins(RISCVInstruction::addi(OperandSize::S64, SP, -8, SP));
            self.store(OperandSize::S64, SP, T1, 0);
            
            self.emit_ins(RISCVInstruction::jal(self.relative_to_anchor(anchor, 0), RA));
            self.load(OperandSize::S64, SP, 0, RA);
            self.emit_ins(RISCVInstruction::addi(OperandSize::S64, SP, 8, SP));
            if let Some(dst) = dst {
                self.emit_ins(RISCVInstruction::mov(OperandSize::S64, REGISTER_SCRATCH, dst));
            }
        } else if let Some(dst) = dst {
            match len {
                1 => self.load(OperandSize::S8, REGISTER_SCRATCH, 0, dst),
                2 => self.load(OperandSize::S16, REGISTER_SCRATCH, 0,dst),
                4 => self.load(OperandSize::S32, REGISTER_SCRATCH, 0,dst),
                8 => self.load(OperandSize::S64, REGISTER_SCRATCH, 0,dst),
                _ => unreachable!(),
            }
        } else {
            // use temporary reg T5 to optimize the workload
            self.load(OperandSize::S64, SP, stack_slot_of_value_to_store, T5);
            match len {
                1 => self.store(OperandSize::S8, T5, REGISTER_SCRATCH, 0),
                2 => self.store(OperandSize::S16, T5, REGISTER_SCRATCH, 0),
                4 => self.store(OperandSize::S32, T5, REGISTER_SCRATCH, 0),
                8 => self.store(OperandSize::S64, T5, REGISTER_SCRATCH, 0),
                _ => unreachable!(),
            }
        }
    }

    fn emit_subroutines(&mut self){
        // Routine for instruction tracing
        if self.config.enable_register_tracing {
            self.set_anchor(ANCHOR_TRACE);
            self.emit_ins(RISCVInstruction::addi(OperandSize::S64, SP, -8, SP));
            self.emit_ins(RISCVInstruction::store(OperandSize::S64, SP, REGISTER_SCRATCH, 0));
            self.emit_ins(RISCVInstruction::addi(OperandSize::S64, SP, REGISTER_MAP.len() as i64 * (-8), SP));
            let mut current_offset = 0;
            for reg in REGISTER_MAP.iter() { // here the data is stored from lower addresses to higher addresses. Therefore, there is no need for .rev()
                self.store(OperandSize::S64, SP, *reg, current_offset);
                current_offset += 8;
            }
            self.emit_ins(RISCVInstruction::mov(OperandSize::S64, SP, REGISTER_MAP[0]));
            self.emit_ins(RISCVInstruction::addi(OperandSize::S64, SP, -8 * 3, SP));
            self.emit_rust_call(Value::Constant64(Vec::<crate::static_analysis::RegisterTraceEntry>::push as *const u8 as i64, false), &[
                Argument { index: 1, value: Value::Register(REGISTER_MAP[0]) }, // registers
                Argument { index: 0, value: Value::RegisterPlusConstant32(REGISTER_PTR_TO_VM, self.slot_in_vm(RuntimeEnvironmentSlot::RegisterTrace), false) },
            ], None); 
            // Pop stack and return
            self.emit_ins(RISCVInstruction::addi(OperandSize::S64, SP, 8 * 3, SP)); // RSP += 8 * 3;
            self.load(OperandSize::S64, SP, 0, REGISTER_MAP[0]);
            self.emit_ins(RISCVInstruction::addi(OperandSize::S64, SP, 8, SP));
            self.emit_ins(RISCVInstruction::addi(OperandSize::S64, SP, 8 * (REGISTER_MAP.len() - 1) as i64, SP));
            self.load(OperandSize::S64, SP, 0, REGISTER_SCRATCH);
            self.emit_ins(RISCVInstruction::addi(OperandSize::S64, SP, 8, SP));
            self.emit_ins(RISCVInstruction::return_near());
        }

        // Epilogue
        self.set_anchor(ANCHOR_EPILOGUE);
        if self.config.enable_instruction_meter {
            // REGISTER_INSTRUCTION_METER -= 1;
            self.emit_ins(RISCVInstruction::addi(OperandSize::S64, REGISTER_INSTRUCTION_METER, -1, REGISTER_INSTRUCTION_METER));
            // REGISTER_INSTRUCTION_METER -= pc;
            self.emit_ins(RISCVInstruction::sub(OperandSize::S64, REGISTER_INSTRUCTION_METER, REGISTER_SCRATCH, REGISTER_INSTRUCTION_METER)); 
            // REGISTER_INSTRUCTION_METER -= *PreviousInstructionMeter;
            self.load(OperandSize::S64, REGISTER_PTR_TO_VM, self.slot_in_vm(RuntimeEnvironmentSlot::PreviousInstructionMeter) as i64, T5);
            self.emit_ins(RISCVInstruction::sub(OperandSize::S64, REGISTER_INSTRUCTION_METER, T5, REGISTER_INSTRUCTION_METER));
            // REGISTER_INSTRUCTION_METER = -REGISTER_INSTRUCTION_METER;
            self.emit_ins(RISCVInstruction::sub(OperandSize::S64, ZERO, REGISTER_INSTRUCTION_METER, REGISTER_INSTRUCTION_METER));
            // *DueInsnCount = REGISTER_INSTRUCTION_METER;
            self.store(OperandSize::S64, REGISTER_PTR_TO_VM, REGISTER_INSTRUCTION_METER, self.slot_in_vm(RuntimeEnvironmentSlot::DueInsnCount) as i64);
        }

        // Restore stack pointer in case we did not exit gracefully
        self.load(OperandSize::S64, REGISTER_PTR_TO_VM, self.slot_in_vm(RuntimeEnvironmentSlot::HostStackPointer) as i64, SP);
        self.emit_ins(RISCVInstruction::mov(OperandSize::S64, S6, RA)); // RA = REGISTER_SCRATCH
        self.emit_ins(RISCVInstruction::return_near());
        
        // Handler for EbpfError::ExceededMaxInstructions
        self.set_anchor(ANCHOR_THROW_EXCEEDED_MAX_INSTRUCTIONS);
        self.emit_set_exception_kind(EbpfError::ExceededMaxInstructions);
        self.emit_ins(RISCVInstruction::mov(OperandSize::S64, REGISTER_INSTRUCTION_METER, REGISTER_SCRATCH)); // REGISTER_SCRATCH = REGISTER_INSTRUCTION_METER;
        // Fall through

        // Epilogue for errors
        self.set_anchor(ANCHOR_THROW_EXCEPTION_UNCHECKED);
        self.store(OperandSize::S64, REGISTER_PTR_TO_VM, REGISTER_SCRATCH, (self.slot_in_vm(RuntimeEnvironmentSlot::Registers) + 11 * std::mem::size_of::<u64>() as i32) as i64); // registers[11] = pc;
        self.emit_ins(RISCVInstruction::jal(self.relative_to_anchor(ANCHOR_EPILOGUE, 0), ZERO));

        // Quit gracefully
        self.set_anchor(ANCHOR_EXIT); 
        if self.config.enable_instruction_meter {
            self.emit_ins(RISCVInstruction::addi(OperandSize::S64, REGISTER_INSTRUCTION_METER, 1, REGISTER_INSTRUCTION_METER)); // REGISTER_INSTRUCTION_METER += 1;
        }
        self.load_immediate(OperandSize::S64, T1, self.slot_in_vm(RuntimeEnvironmentSlot::ProgramResult) as i64);
        self.emit_ins(RISCVInstruction::add(OperandSize::S64, REGISTER_PTR_TO_VM, T1, REGISTER_SCRATCH));
        self.store(OperandSize::S64, REGISTER_SCRATCH, REGISTER_MAP[0], std::mem::size_of::<u64>() as i64);
        self.emit_ins(RISCVInstruction::mov(OperandSize::S64, ZERO,  REGISTER_SCRATCH)); // REGISTER_SCRATCH ^= REGISTER_SCRATCH; // REGISTER_SCRATCH = 0;
        self.emit_ins(RISCVInstruction::jal(self.relative_to_anchor(ANCHOR_EPILOGUE, 0), ZERO));
    
        // Handler for exceptions which report their pc
        self.set_anchor(ANCHOR_THROW_EXCEPTION);
        // Validate that we did not reach the instruction meter limit before the exception occured
        self.emit_validate_instruction_count(None);
        self.emit_ins(RISCVInstruction::jal(self.relative_to_anchor(ANCHOR_THROW_EXCEPTION_UNCHECKED, 0), ZERO));

        // Handler for EbpfError::CallDepthExceeded
        self.set_anchor(ANCHOR_CALL_DEPTH_EXCEEDED);
        self.emit_set_exception_kind(EbpfError::CallDepthExceeded);
        self.emit_ins(RISCVInstruction::jal(self.relative_to_anchor(ANCHOR_THROW_EXCEPTION, 0), ZERO));
        
        // Handler for EbpfError::CallOutsideTextSegment
        self.set_anchor(ANCHOR_CALL_REG_OUTSIDE_TEXT_SEGMENT);
        self.emit_set_exception_kind(EbpfError::CallOutsideTextSegment);
        self.load(OperandSize::S64, SP, -8, REGISTER_SCRATCH); 
        self.emit_ins(RISCVInstruction::jal(self.relative_to_anchor(ANCHOR_THROW_EXCEPTION, 0), ZERO));

        // Handler for EbpfError::DivideByZero
        self.set_anchor(ANCHOR_DIV_BY_ZERO);
        self.emit_set_exception_kind(EbpfError::DivideByZero);
        self.emit_ins(RISCVInstruction::jal(self.relative_to_anchor(ANCHOR_THROW_EXCEPTION, 0), ZERO));

        // Handler for EbpfError::DivideOverflow
        self.set_anchor(ANCHOR_DIV_OVERFLOW);
        self.emit_set_exception_kind(EbpfError::DivideOverflow);
        self.emit_ins(RISCVInstruction::jal(self.relative_to_anchor(ANCHOR_THROW_EXCEPTION, 0), ZERO));

        // See `ANCHOR_INTERNAL_FUNCTION_CALL_REG` for more details.
        self.set_anchor(ANCHOR_CALL_REG_UNSUPPORTED_INSTRUCTION);
        self.load(OperandSize::S64, SP, -8, REGISTER_SCRATCH); // Retrieve the current program counter from the stack
        self.load(OperandSize::S64, SP, 0, REGISTER_MAP[0]); // Restore the clobbered REGISTER_MAP[0]
        self.emit_ins(RISCVInstruction::addi(OperandSize::S64, SP, 8, SP));
        // Fall through

        // Handler for EbpfError::UnsupportedInstruction
        self.set_anchor(ANCHOR_CALL_UNSUPPORTED_INSTRUCTION);
        if self.config.enable_register_tracing {
            self.emit_ins(RISCVInstruction::addi(OperandSize::S64, SP, -8, SP));
            self.store(OperandSize::S64, SP, RA, 0);
            self.emit_ins(RISCVInstruction::jal(self.relative_to_anchor(ANCHOR_TRACE, 0), RA));
            self.load(OperandSize::S64, SP, 0, RA);
            self.emit_ins(RISCVInstruction::addi(OperandSize::S64, SP, 8, SP));
        }
        self.emit_set_exception_kind(EbpfError::UnsupportedInstruction);
        self.emit_ins(RISCVInstruction::jal(self.relative_to_anchor(ANCHOR_THROW_EXCEPTION, 0), ZERO));

        //Routine for external functions
        self.set_anchor(ANCHOR_EXTERNAL_FUNCTION_CALL);
        self.load_immediate(OperandSize::S64, T1, -1);
        self.emit_ins(RISCVInstruction::addi(OperandSize::S64, SP, -8, SP));
        self.store(OperandSize::S64, SP, T1, 0);// Used as PC value in error case, acts as stack padding otherwise
        if self.config.enable_instruction_meter {
            self.store(OperandSize::S64, REGISTER_PTR_TO_VM, REGISTER_INSTRUCTION_METER, self.slot_in_vm(RuntimeEnvironmentSlot::DueInsnCount) as i64); // *DueInsnCount = REGISTER_INSTRUCTION_METER;
        }
        self.emit_rust_call(Value::Register(REGISTER_SCRATCH), &[
            Argument { index: 5, value: Value::Register(ARGUMENT_REGISTERS[5]) },
            Argument { index: 4, value: Value::Register(ARGUMENT_REGISTERS[4]) },
            Argument { index: 3, value: Value::Register(ARGUMENT_REGISTERS[3]) },
            Argument { index: 2, value: Value::Register(ARGUMENT_REGISTERS[2]) },
            Argument { index: 1, value: Value::Register(ARGUMENT_REGISTERS[1]) },
            Argument { index: 0, value: Value::Register(REGISTER_PTR_TO_VM) },
        ], None);
        if self.config.enable_instruction_meter {
            self.load(OperandSize::S64, REGISTER_PTR_TO_VM, self.slot_in_vm(RuntimeEnvironmentSlot::PreviousInstructionMeter) as i64, REGISTER_INSTRUCTION_METER); // REGISTER_INSTRUCTION_METER = *PreviousInstructionMeter;
        }

        //Test if result indicates that an error occured
        // self.emit_result_is_err(REGISTER_SCRATCH);
        let ok = ProgramResult::Ok(0);
        let ok_discriminant = ok.discriminant();
        self.load_immediate(OperandSize::S64, T1, self.slot_in_vm(RuntimeEnvironmentSlot::ProgramResult) as i64);
        self.emit_ins(RISCVInstruction::add(OperandSize::S64, REGISTER_PTR_TO_VM, T1, T5));
        // self.load(OperandSize::S64, REGISTER_PTR_TO_VM, self.slot_in_vm(RuntimeEnvironmentSlot::ProgramResult) as i64, T5);
        
        self.load_immediate(OperandSize::S64, T1, ok_discriminant as i64);
        self.load(OperandSize::S64, SP, 0, REGISTER_SCRATCH);
        self.emit_ins(RISCVInstruction::addi(OperandSize::S64, SP, 8, SP));
        self.load(OperandSize::S64, T5, 0, T4);
        self.emit_ins(RISCVInstruction::bne(OperandSize::S32, T1, T4, self.relative_to_anchor(ANCHOR_EPILOGUE, 0)));
        // Store Ok value in result register
        self.load_immediate(OperandSize::S64, T1, self.slot_in_vm(RuntimeEnvironmentSlot::ProgramResult) as i64);
        self.emit_ins(RISCVInstruction::add(OperandSize::S64, REGISTER_PTR_TO_VM, T1, REGISTER_SCRATCH));
        // self.load(OperandSize::S64, REGISTER_PTR_TO_VM, self.slot_in_vm(RuntimeEnvironmentSlot::ProgramResult) as i64, REGISTER_SCRATCH);
        self.load(OperandSize::S64, REGISTER_SCRATCH, 8, REGISTER_MAP[0]);
        self.emit_ins(RISCVInstruction::return_near());

        // Routine for prologue of emit_internal_call()
        self.set_anchor(ANCHOR_INTERNAL_FUNCTION_CALL_PROLOGUE);
        self.emit_validate_instruction_count(None);
        self.emit_ins(RISCVInstruction::addi(OperandSize::S64, SP, -8 * (SCRATCH_REGS + 1) as i64, SP));
        self.store(OperandSize::S64, SP, REGISTER_SCRATCH,  0); // Save original REGISTER_SCRATCH
        self.load(OperandSize::S64, SP, 8 * (SCRATCH_REGS + 1) as i64, REGISTER_SCRATCH); // Load return address
        for (i, reg) in REGISTER_MAP.iter().skip(FIRST_SCRATCH_REG).take(SCRATCH_REGS).enumerate() {
            self.store(OperandSize::S64, SP, *reg,  8 * (SCRATCH_REGS - i + 1) as i64); // Push SCRATCH_REG
        }
        // Push the caller's frame pointer. The code to restore it is emitted at the end of emit_internal_call().
        self.store(OperandSize::S64, SP, REGISTER_MAP[FRAME_PTR_REG],  8);

        // Push return address and restore original REGISTER_SCRATCH
        self.load(OperandSize::S64, SP, 0, T5);
        self.store(OperandSize::S64, SP, REGISTER_SCRATCH, 0);
        self.emit_ins(RISCVInstruction::mov(OperandSize::S64, T5, REGISTER_SCRATCH));

        // Increase env.call_depth
        let call_depth_access = self.slot_in_vm(RuntimeEnvironmentSlot::CallDepth) as i64;
        self.load(OperandSize::S64, REGISTER_PTR_TO_VM, call_depth_access, T5);
        self.emit_ins(RISCVInstruction::addi(OperandSize::S64, T5, 1, T5)); // env.call_depth += 1;
        self.store(OperandSize::S64, REGISTER_PTR_TO_VM, T5, call_depth_access);
        // If env.call_depth == self.config.max_call_depth, throw CallDepthExceeded
        self.load_immediate(OperandSize::S64, T1, self.config.max_call_depth as i64);
        self.emit_ins(RISCVInstruction::beq(OperandSize::S64, T5, T1, self.relative_to_anchor(ANCHOR_CALL_DEPTH_EXCEEDED, 0)));

        // Setup the frame pointer for the new frame. What we do depends on whether we're using dynamic or fixed frames.
        if self.executable.get_sbpf_version().automatic_stack_frame_bump() {
            // With fixed frames we start the new frame at the next fixed offset
            let stack_frame_size = self.config.stack_frame_size as i64 * if !self.executable.get_sbpf_version().manual_stack_frame_bump() && self.config.enable_stack_frame_gaps { 2 } else { 1 };
            self.load_immediate(OperandSize::S32, T1, stack_frame_size);
            self.emit_ins(RISCVInstruction::add(OperandSize::S64, REGISTER_MAP[FRAME_PTR_REG], T1, REGISTER_MAP[FRAME_PTR_REG])); // env.stack_pointer += stack_frame_size;
        }
        // self.emit_ins(RISCVInstruction::addi(OperandSize::S64, SP, 8, SP));
        self.emit_ins(RISCVInstruction::return_near());

        // Routine for emit_internal_call(Value::Register())
        // Inputs: Guest current pc in X86IndirectAccess::OffsetIndexShift(-16, RSP, 0), Guest target address in REGISTER_SCRATCH
        // Outputs: Guest current pc in X86IndirectAccess::OffsetIndexShift(-16, RSP, 0), Guest target pc in REGISTER_SCRATCH, Host target address in RIP
        self.set_anchor(ANCHOR_INTERNAL_FUNCTION_CALL_REG);
        self.emit_ins(RISCVInstruction::addi(OperandSize::S64, SP, -8, SP));
        self.store(OperandSize::S64, SP, REGISTER_MAP[0], 0);
        // Calculate offset relative to instruction_addresses
        self.load_immediate(OperandSize::S64, REGISTER_MAP[0], self.program_vm_addr as i64);
        self.emit_ins(RISCVInstruction::sub(OperandSize::S64, REGISTER_SCRATCH, REGISTER_MAP[0], REGISTER_SCRATCH)); // guest_target_pc = guest_target_address - self.program_vm_addr;
        // Force alignment of RAX
        self.load_immediate(OperandSize::S64, T5, !(INSN_SIZE as i64 - 1));
        self.emit_ins(RISCVInstruction::and(OperandSize::S64, REGISTER_SCRATCH, T5, REGISTER_SCRATCH)); // guest_target_pc &= !(INSN_SIZE - 1);
        // Bound check
        // if(guest_target_pc >= number_of_instructions * INSN_SIZE) throw CALL_OUTSIDE_TEXT_SEGMENT;
        // if(RAX >= number_of_instructions * INSN_SIZE) throw CALL_OUTSIDE_TEXT_SEGMENT;
        let number_of_instructions = self.result.pc_section.len();
        self.load_immediate(OperandSize::S64, T1, (number_of_instructions * INSN_SIZE) as i64);
        self.emit_ins(RISCVInstruction::bgeu(OperandSize::S64, REGISTER_SCRATCH, T1, self.relative_to_anchor(ANCHOR_CALL_REG_OUTSIDE_TEXT_SEGMENT, 0)));
        // Calculate the target_pc (dst / INSN_SIZE) to update REGISTER_INSTRUCTION_METER
        // and as target pc for potential ANCHOR_CALL_REG_UNSUPPORTED_INSTRUCTION
        let shift_amount = INSN_SIZE.trailing_zeros();
        debug_assert_eq!(INSN_SIZE, 1 << shift_amount);
        self.emit_ins(RISCVInstruction::srli(OperandSize::S64, REGISTER_SCRATCH, shift_amount as i64, REGISTER_SCRATCH));
        // Load host target_address from self.result.pc_section
        // debug_assert_eq!(INSN_SIZE, 8); // Because the instruction size is also the slot size we do not need to shift the offset
        self.load_immediate(OperandSize::S64, REGISTER_MAP[0], self.result.pc_section.as_ptr() as i64); // host_target_address = self.result.pc_section;
        self.emit_ins(RISCVInstruction::slli(OperandSize::S64, REGISTER_SCRATCH, 2, T5));
        self.emit_ins(RISCVInstruction::add(OperandSize::S64, REGISTER_MAP[0], T5, T5)); 
        self.load(OperandSize::S32, T5, 0, REGISTER_MAP[0]); // host_target_address = self.result.pc_section[guest_target_pc];
        // Check destination is valid
        self.load_immediate(OperandSize::S32, T1, 0x8000_0000);
        self.emit_ins(RISCVInstruction::and(OperandSize::S64, REGISTER_MAP[0], T1, T1));
        self.emit_ins(RISCVInstruction::bne(OperandSize::S64, T1, ZERO, self.relative_to_anchor(ANCHOR_CALL_REG_UNSUPPORTED_INSTRUCTION, 0)));
        self.load_immediate(OperandSize::S32, T1, 0x8000_0000);
        self.emit_ins(RISCVInstruction::addi(OperandSize::S64, T1, -1, T1));
        self.emit_ins(RISCVInstruction::and(OperandSize::S64, REGISTER_MAP[0], T1, REGISTER_MAP[0]));
        // A version of `self.emit_profile_instruction_count(None);` which reads self.pc from the stack
        self.load(OperandSize::S64, SP, -8, T5); // Load guest_current_pc
        self.emit_ins(RISCVInstruction::sub(OperandSize::S64, REGISTER_INSTRUCTION_METER, T5, REGISTER_INSTRUCTION_METER)); // instruction_meter -= guest_current_pc;
        self.emit_ins(RISCVInstruction::addi(OperandSize::S64, REGISTER_INSTRUCTION_METER, -1, REGISTER_INSTRUCTION_METER)); // instruction_meter -= 1;
        self.emit_ins(RISCVInstruction::add(OperandSize::S64, REGISTER_INSTRUCTION_METER, REGISTER_SCRATCH, REGISTER_INSTRUCTION_METER)); // instruction_meter += guest_target_pc;
        // Offset host_target_address by self.result.text_section
        self.load_immediate(OperandSize::S64, T5, self.result.text_section.as_ptr() as i64);          // REGISTER_SCRATCH = self.result.text_section;
        self.emit_ins(RISCVInstruction::add(OperandSize::S64, REGISTER_MAP[0], T5, REGISTER_MAP[0])); // host_target_address += self.result.text_section;
        // Restore the clobbered REGISTER_MAP[0]
        self.load(OperandSize::S64, SP, 0, T5);
        self.store(OperandSize::S64, SP, REGISTER_MAP[0], 0);
        self.emit_ins(RISCVInstruction::mov(OperandSize::S64, REGISTER_MAP[0], T6)); // save host_target_address in T6
        self.emit_ins(RISCVInstruction::mov(OperandSize::S64, T5, REGISTER_MAP[0]));

        self.emit_ins(RISCVInstruction::addi(OperandSize::S64, SP, 8, SP));
        self.emit_ins(RISCVInstruction::jalr(T6, 0, ZERO)); // Tail call to host_target_address

        // Translates a vm memory address to a host memory address
        let lower_key = self.immediate_value_key as i32 as i64;
        for (anchor_base, len) in &[
            (0, 1i32), (0, 2i32), (0, 4i32), (0, 8i32),
            (4, 1i32), (4, 2i32), (4, 4i32), (4, 8i32),
            (8, 1i32), (8, 2i32), (8, 4i32), (8, 8i32),
        ] {
            let target_offset = *anchor_base + len.trailing_zeros() as usize;
            self.set_anchor(ANCHOR_TRANSLATE_MEMORY_ADDRESS + target_offset);
            // call MemoryMapping::(load|store) storing the result in RuntimeEnvironmentSlot::ProgramResult
            if *anchor_base == 0 {
                let load = match len {
                    1 => MemoryMapping::load::<u8> as *const u8 as i64,
                    2 => MemoryMapping::load::<u16> as *const u8 as i64,
                    4 => MemoryMapping::load::<u32> as *const u8 as i64,
                    8 => MemoryMapping::load::<u64> as *const u8 as i64,
                    _ => unreachable!()
                };
                self.emit_rust_call(Value::Constant64(load, false), &[
                    Argument { index: 2, value: Value::Register(REGISTER_SCRATCH) }, // Specify first as the src register could be overwritten by other arguments
                    Argument { index: 3, value: Value::Constant64(0, false) }, // self.pc is set later
                    Argument { index: 1, value: Value::RegisterPlusConstant32(REGISTER_PTR_TO_VM, self.slot_in_vm(RuntimeEnvironmentSlot::MemoryMapping), false) },
                    Argument { index: 0, value: Value::RegisterPlusConstant32(REGISTER_PTR_TO_VM, self.slot_in_vm(RuntimeEnvironmentSlot::ProgramResult), false) },
                ], None);
            } else {
                if *anchor_base == 8 {
                    // Second half of emit_sanitized_load_immediate(stack_slot_of_value_to_store, constant)
                    self.load(OperandSize::S64, SP, -80, T5);
                    self.load_immediate(OperandSize::S64, T1, lower_key);
                    self.emit_ins(RISCVInstruction::add(OperandSize::S64, T5, T1, T5));
                    self.store(OperandSize::S64, SP, T5, -80);
                }
                let store = match len {
                    1 => MemoryMapping::store::<u8> as *const u8 as i64,
                    2 => MemoryMapping::store::<u16> as *const u8 as i64,
                    4 => MemoryMapping::store::<u32> as *const u8 as i64,
                    8 => MemoryMapping::store::<u64> as *const u8 as i64,
                    _ => unreachable!()
                };
                self.emit_rust_call(Value::Constant64(store, false), &[
                    Argument { index: 3, value: Value::Register(REGISTER_SCRATCH) }, // Specify first as the src register could be overwritten by other arguments
                    Argument { index: 2, value: Value::RegisterIndirect(SP, -8, false) },
                    Argument { index: 4, value: Value::Constant64(0, false) }, // self.pc is set later
                    Argument { index: 1, value: Value::RegisterPlusConstant32(REGISTER_PTR_TO_VM, self.slot_in_vm(RuntimeEnvironmentSlot::MemoryMapping), false) },
                    Argument { index: 0, value: Value::RegisterPlusConstant32(REGISTER_PTR_TO_VM, self.slot_in_vm(RuntimeEnvironmentSlot::ProgramResult), false) },
                ], None);
            }

            // Throw error if the result indicates one
            // self.emit_result_is_err(REGISTER_SCRATCH);
            let ok = ProgramResult::Ok(0);
            let ok_discriminant = ok.discriminant();
            self.load_immediate(OperandSize::S64, T1, self.slot_in_vm(RuntimeEnvironmentSlot::ProgramResult) as i64);
            self.emit_ins(RISCVInstruction::add(OperandSize::S64, REGISTER_PTR_TO_VM, T1, T5));
            
            self.load_immediate(OperandSize::S64, T1, ok_discriminant as i64);
            self.load(OperandSize::S64, SP, 0, REGISTER_SCRATCH); // REGISTER_SCRATCH = self.pc
            self.emit_ins(RISCVInstruction::addi(OperandSize::S64, SP, 8, SP));

            self.load(OperandSize::S64, T5, 0, T4);
            self.emit_ins(RISCVInstruction::bne(OperandSize::S32, T1, T4, self.relative_to_anchor(ANCHOR_THROW_EXCEPTION, 0)));

            if *anchor_base == 0 { // AccessType::Load
                // unwrap() the result into REGISTER_SCRATCH
                self.load(OperandSize::S64, REGISTER_PTR_TO_VM, (self.slot_in_vm(RuntimeEnvironmentSlot::ProgramResult) + std::mem::size_of::<u64>() as i32) as i64, REGISTER_SCRATCH);
            }
            
            self.emit_ins(RISCVInstruction::return_near());
        }
    }

    fn set_anchor(&mut self, anchor: usize) {
        self.anchors[anchor] = unsafe { self.result.text_section.as_ptr().add(self.offset_in_text_section) };
    }

    // instruction_length = 4 bits for RISC-V
    #[inline]
    fn relative_to_anchor(&self, anchor: usize, instruction_length: usize) -> i64 {
        let instruction_end = unsafe { self.result.text_section.as_ptr().add(self.offset_in_text_section).add(instruction_length) };
        let destination = self.anchors[anchor];
        debug_assert!(!destination.is_null());
        (unsafe { destination.offset_from(instruction_end) } as i64) // Relative jump
    }

    #[inline]
    fn relative_to_target_pc(&mut self, target_pc: usize, instruction_length: usize) -> i32 {
        let instruction_end = unsafe { self.result.text_section.as_ptr().add(self.offset_in_text_section).add(instruction_length) };
        let destination = if self.result.pc_section[target_pc] != 0 {
            // Backward jump
            &self.result.text_section[self.result.pc_section[target_pc] as usize & (i32::MAX as u32 as usize)] as *const u8
        } else {
            // Forward jump, needs relocation
            self.text_section_jumps.push(Jump { location: unsafe { instruction_end.sub(0) }, target_pc });
            return 0;
        };
        debug_assert!(!destination.is_null());
        (unsafe { destination.offset_from(instruction_end) } as i32) // Relative jump
    }

    fn emit_rust_call(&mut self, target: Value, arguments: &[Argument], result_reg: Option<u8>){
        let mut saved_registers = CALLER_SAVED_REGISTERS.to_vec();
        if let Some(reg) = result_reg {
            if let Some(dst) = saved_registers.iter().position(|x| *x == reg) {
                saved_registers.remove(dst);
            }
        }

        // Save registers on stack
        let saved_registers_len = saved_registers.len();
        self.emit_ins(RISCVInstruction::addi(OperandSize::S64, SP, -8 * saved_registers_len as i64, SP));
        let mut current_offset = 0;
        for reg in saved_registers.iter() {
            self.store(OperandSize::S64, SP, *reg, current_offset);
            current_offset += 8;
        }

        let stack_arguments = arguments.len().saturating_sub(ARGUMENT_REGISTERS.len()) as i64;
        if stack_arguments % 2 != 0 {
            // If we're going to pass an odd number of stack args we need to pad
            // to preserve alignment
            self.emit_ins(RISCVInstruction::addi(OperandSize::S64, SP, -8, SP));
        }

        // Pass arguments
        for argument in arguments {
            let is_stack_argument = argument.index >= ARGUMENT_REGISTERS.len();
            let dst = if is_stack_argument {
                SP // Never used
            } else {
                ARGUMENT_REGISTERS[argument.index]
            };
            match argument.value {
                Value::Register(reg) => {
                    if is_stack_argument {
                        self.emit_ins(RISCVInstruction::addi(OperandSize::S64, SP, -8, SP));
                        self.store(OperandSize::S64, SP, reg, 0);
                    } else if reg != dst {
                        self.emit_ins(RISCVInstruction::mov(OperandSize::S64, reg, dst));
                    }
                },
                Value::RegisterIndirect(reg, offset, user_provided) => {
                    debug_assert!(!user_provided);
                    if is_stack_argument {
                        debug_assert!(reg != SP);
                        self.emit_ins(RISCVInstruction::addi(OperandSize::S64, SP, -8, SP));
                        self.store(OperandSize::S64, SP, reg, offset as i64);
                    } else if reg == SP {
                        self.load(OperandSize::S64, SP, offset as i64, dst); 
                    } else {
                        self.load(OperandSize::S64, reg, offset as i64, dst);
                    }
                },
                Value::RegisterPlusConstant32(reg, offset, user_provided) => {
                    debug_assert!(!user_provided);
                    if is_stack_argument {
                        self.emit_ins(RISCVInstruction::addi(OperandSize::S64, SP, -8, SP));
                        self.store(OperandSize::S64, SP, reg, 0);
                        self.load(OperandSize::S64, SP, 0, T5);
                        self.emit_ins(RISCVInstruction::addi(OperandSize::S64, T5, 1, T5));
                        self.store(OperandSize::S64, SP, T5, 0);
                    } else if reg == SP {
                        self.load_immediate(OperandSize::S64, T1, offset as i64);
                        self.emit_ins(RISCVInstruction::add(OperandSize::S64, SP, T1, dst));
                    } else {
                        self.load_immediate(OperandSize::S64, T1, offset as i64);
                        self.emit_ins(RISCVInstruction::add(OperandSize::S64, reg, T1, dst));
                    }
                },
                Value::RegisterPlusConstant64(reg, offset, user_provided) => {
                    debug_assert!(!user_provided);
                    if is_stack_argument {
                        self.emit_ins(RISCVInstruction::addi(OperandSize::S64, SP, -8, SP));
                        self.store(OperandSize::S64, SP, reg, 0);
                        self.load(OperandSize::S64, SP, 0, T5);
                        self.emit_ins(RISCVInstruction::addi(OperandSize::S64, T5, 1, T5));
                        self.store(OperandSize::S64, SP, T5, 0);
                    } else {
                        self.load_immediate(OperandSize::S64, T1, offset as i64);
                        self.emit_ins(RISCVInstruction::add(OperandSize::S64, reg, T1, dst));
                    }
                },
                Value::Constant64(value, user_provided) => {
                    debug_assert!(!user_provided && !is_stack_argument);
                    self.load_immediate(OperandSize::S64, dst, value);
                },
            }
        }
        match target {
            Value::Register(reg) => {
                self.emit_ins(RISCVInstruction::jalr(reg, 0, RA));
            },
            Value::Constant64(value, user_provided) => {
                debug_assert!(!user_provided);
                self.load_immediate(OperandSize::S64, T1, value);
                self.emit_ins(RISCVInstruction::jalr(T1, 0, RA));
            },
            _ => {
                #[cfg(debug_assertions)]
                unreachable!();
            }
        }

        // Save returned value in result register
        if let Some(reg) = result_reg {
            self.emit_ins(RISCVInstruction::mov(OperandSize::S64, A0, reg));
        }

        // Restore registers from stack
        self.emit_ins(RISCVInstruction::addi(OperandSize::S64, SP, if stack_arguments % 2 != 0 { stack_arguments + 1 } else { stack_arguments } * 8, SP));

        let mut current_offset = 0;
        for reg in saved_registers.iter() {
            self.load(OperandSize::S64, SP, current_offset, *reg);
            current_offset += 8;
        }
        self.emit_ins(RISCVInstruction::addi(OperandSize::S64, SP, 8 * saved_registers_len as i64, SP));
    }

    #[inline]
    fn call_immediate(&mut self, offset:i64){
        self.emit_ins(RISCVInstruction::addi(OperandSize::S64, SP, -8, SP));
        self.store(OperandSize::S64, SP, RA, 0);
        self.emit_ins(RISCVInstruction::jal(offset, RA));
        self.load(OperandSize::S64, SP, 0, RA);
        self.emit_ins(RISCVInstruction::addi(OperandSize::S64, SP, 8, SP));
    }
    
    #[inline]
    fn call_reg(&mut self, dst: u8){
        self.emit_ins(RISCVInstruction::addi(OperandSize::S64, SP, -8, SP));
        self.store(OperandSize::S64, SP, RA, 0);
        self.emit_ins(RISCVInstruction::jalr(dst, 0,RA));
        self.load(OperandSize::S64, SP, 0, RA);
        self.emit_ins(RISCVInstruction::addi(OperandSize::S64, SP, 8, SP));
    }

    #[inline]
    fn emit_internal_call(&mut self, dst: Value) {
        // Store PC in case the bounds check fails
        self.load_immediate(OperandSize::S64, REGISTER_SCRATCH, self.pc as i64);
        self.emit_ins(RISCVInstruction::addi(OperandSize::S64, SP, -8, SP));
        self.store(OperandSize::S64, SP, RA, 0);
        self.emit_ins(RISCVInstruction::jal(self.relative_to_anchor(ANCHOR_INTERNAL_FUNCTION_CALL_PROLOGUE, 0), RA));
        self.load(OperandSize::S64, SP, 0, RA);
        self.emit_ins(RISCVInstruction::addi(OperandSize::S64, SP, 8, SP));

        match dst {
            Value::Register(reg) => {
                // REGISTER_SCRATCH contains self.pc, and we must store it for proper error handling.
                // We can discard the value if callx succeeds, so we are not incrementing the stack pointer (RSP).
                self.store(OperandSize::S64, SP, REGISTER_SCRATCH, -24); 
                // Move guest_target_address into REGISTER_SCRATCH
                self.emit_ins(RISCVInstruction::mov(OperandSize::S64, reg, REGISTER_SCRATCH));
                
                self.emit_ins(RISCVInstruction::addi(OperandSize::S64, SP, -8, SP));
                self.store(OperandSize::S64, SP, RA, 0);
                self.emit_ins(RISCVInstruction::jal(self.relative_to_anchor(ANCHOR_INTERNAL_FUNCTION_CALL_REG, 0), RA));
                self.load(OperandSize::S64, SP, 0, RA);
                self.emit_ins(RISCVInstruction::addi(OperandSize::S64, SP, 8, SP));
            },
            Value::Constant64(target_pc, user_provided) => {
                debug_assert!(user_provided);
                self.emit_profile_instruction_count(Some(target_pc as usize));
                if user_provided && self.should_sanitize_constant(target_pc) {
                    self.emit_sanitized_load_immediate(REGISTER_SCRATCH, target_pc);
                } else {
                    self.load_immediate(OperandSize::S64, REGISTER_SCRATCH, target_pc);
                }
                
                self.emit_ins(RISCVInstruction::addi(OperandSize::S64, SP, -8, SP));
                self.store(OperandSize::S64, SP, RA, 0);
                let jump_offset = self.relative_to_target_pc(target_pc as usize, 0) as i64;
                self.emit_ins(RISCVInstruction::jal(jump_offset, RA));
                self.load(OperandSize::S64, SP, 0, RA);
                self.emit_ins(RISCVInstruction::addi(OperandSize::S64, SP, 8, SP));
            },
            _ => {
                #[cfg(debug_assertions)]
                unreachable!();
            }
        }

        self.emit_undo_profile_instruction_count(0);

        // Restore the previous frame pointer
        self.load(OperandSize::S64, SP, 0, REGISTER_MAP[FRAME_PTR_REG]);
        self.emit_ins(RISCVInstruction::addi(OperandSize::S64, SP, 8, SP)); 
        let mut current_offset = 0;
        for reg in REGISTER_MAP.iter().skip(FIRST_SCRATCH_REG).take(SCRATCH_REGS).rev() {
            self.load(OperandSize::S64, SP, current_offset, *reg);
            current_offset += 8;
        }
        self.emit_ins(RISCVInstruction::addi(OperandSize::S64, SP, current_offset, SP));
    }

    fn resolve_jumps(&mut self) {
        // Relocate forward jumps
        for jump in &self.text_section_jumps {
            let destination = &self.result.text_section[self.result.pc_section[jump.target_pc] as usize & (i32::MAX as u32 as usize)] as *const u8;
            let offset_value = 
                unsafe { destination.offset_from(jump.location) } as i32 ;// Relative jump
            let address: *const u32 = jump.location as *const u32; 
    
            unsafe {
                // Rewrite the instruction at jump.location with the correct offset
                let original_instruction = *address;
                
                let op = original_instruction & 0x7f;
                if op != 0x6f as u32 {
                    // B type instrustion (Branch)
                    let imm_11 = (offset_value & 0x800) >> 4; // Extract the 12th bit of the immediate number and move it to bit[7]
                    let imm_4_1 = (offset_value & 0x1E) << 7; // Extract bits [1:4] of the immediate number and move them to bits[8:11]
                    let imm_10_5 = (offset_value & 0x7E0) << 20; // Extract bits [5:10] of the immediate number and move them to bits[25:30]
                    let imm_12 = (offset_value & 0x1000) << 19; // Extract the 13th bit of the immediate number and move it to bit[31]
                    let rs2_rs1_funct3 = (original_instruction & 0x1FFF000) as i32;
                    let opcode = (original_instruction & 0x7F) as i32;
                    let instruction = imm_12 | imm_10_5 | rs2_rs1_funct3 | imm_4_1 | imm_11 | opcode;
                    unsafe { ptr::write_unaligned(jump.location as *mut i32, instruction); }
                } else {
                    // J type instruction (JAL)
                    let imm_19_12 = offset_value & 0xFF000; // Extract immediate bits [12:19]
                    let imm_11 = (offset_value & 0x800) << 9; // Extract immediate bit [11]
                    let imm_10_1 = (offset_value & 0x7FE) << 20; // Extract immediate bits [1:10]
                    let imm_20 = (offset_value & 0x100000) << 11; // Extract immediate bit [20]
                    let rd = (original_instruction & 0xF80) as i32;
                    let opcode = 0x6f & 0x7F;
                    let instruction= imm_20 | imm_10_1 | imm_11 | imm_19_12 | rd | opcode;
                    unsafe { ptr::write_unaligned(jump.location as *mut i32, instruction); }
                }
            }         
        }
    }
}

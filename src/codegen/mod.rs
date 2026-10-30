//! Unified JIT and interpreted execution of BPF code ("parrot").
//!
//! Both the JIT and the interpreter are built from the same per-instruction code, generated once
//! per SBPF version by the architecture backend for every possible 16-bit opcode/register prefix
//! of an instruction:
//!
//! - The JIT copies these machine code templates back to back and patches a few fields in each
//!   (see [`arch::TemplateRelocation`]), with no instruction selection at compile time.
//! - The interpreter places the same code into fixed size steps of a dispatch table, each step
//!   followed by epilogue that jumps to the step of the next instruction immediately.
//!
//! TODO: write full README.md for this.

mod generate;
mod templates;
mod x64;

use x64 as arch;

pub use generate::jit_templates;
pub use templates::JitTemplates;

use crate::ebpf;
use crate::elf::Executable;
use crate::error::{EbpfError, ProgramResult};
use crate::program::{JitProgram, SBPFVersion};
use crate::vm::{ContextObject, EbpfVm};
use std::num::NonZeroU64;

const SIG_INVALID_INSN: i8 = -1;

const SIG_EXCEEDED_MAX_INSTRUCTIONS: i8 = -2;

const SIG_CALL_DEPTH_EXCEEDED: i8 = -3;

const SIG_DIVIDE_BY_ZERO: i8 = -4;

const SIG_EXECUTION_OVERRUN: i8 = -5;

const SIG_CALL_OUTSIDE_TEXT_SEGMENT: i8 = -6;

/// `vm.program_result` has already been set.
const SIG_PROGRAM_RESULT: i8 = -7;

/// The initial value of `meter` for executing `bpf` starting at `vm.registers[11]` with
/// `vm.previous_instruction_meter` as the budget.
fn initial_meter<C: ContextObject>(bpf: &[u8], vm: &EbpfVm<C>) -> u64 {
    let pc = vm.registers[11];
    let budget = vm.previous_instruction_meter;
    assert!(
        budget <= u32::MAX as u64,
        "the instruction budget is nonsensical"
    );
    (bpf.as_ptr() as u64).wrapping_add(pc.wrapping_add(budget).wrapping_mul(ebpf::INSN_SIZE as u64))
}

/// Finalize `vm` fields after the generated code has terminated with `exit_code`.
fn finish_execution<C: ContextObject>(
    vm: &mut EbpfVm<C>,
    exit_code: i8,
    meter: u64,
    r0: u64,
    last_pc: u64,
) {
    vm.registers[11] = last_pc.wrapping_sub(1);
    let remaining = if exit_code == SIG_EXCEEDED_MAX_INSTRUCTIONS || (meter as i64) < 0 {
        0
    } else {
        meter / const { NonZeroU64::new(ebpf::INSN_SIZE as u64).unwrap() }
    };
    // Syscalls consume the budget used up to them and update `previous_instruction_meter`.
    vm.due_insn_count = vm.previous_instruction_meter.saturating_sub(remaining);
    use EbpfError::*;
    match exit_code {
        0 => vm.program_result = ProgramResult::Ok(r0),
        // Calls into Rust store their errors into `vm.program_result` themselves.
        SIG_PROGRAM_RESULT => {}
        SIG_EXCEEDED_MAX_INSTRUCTIONS => {
            vm.program_result = ProgramResult::Err(ExceededMaxInstructions)
        }
        SIG_INVALID_INSN => vm.program_result = ProgramResult::Err(UnsupportedInstruction),
        SIG_CALL_DEPTH_EXCEEDED => vm.program_result = ProgramResult::Err(CallDepthExceeded),
        SIG_DIVIDE_BY_ZERO => vm.program_result = ProgramResult::Err(DivideByZero),
        SIG_EXECUTION_OVERRUN => vm.program_result = ProgramResult::Err(ExecutionOverrun),
        SIG_CALL_OUTSIDE_TEXT_SEGMENT => {
            vm.program_result = ProgramResult::Err(CallOutsideTextSegment)
        }
        _ => unreachable!("unexpected exit code {}", exit_code),
    }
}

/// Interpret `executable`, starting at `vm.registers[11]`.
pub fn interpret<C: ContextObject>(executable: &Executable<C>, vm: &mut EbpfVm<C>) {
    arch::enter(executable, None, vm)
}

impl JitProgram {
    pub(crate) fn parrot_invoke<C: ContextObject>(
        &self,
        executable: &Executable<C>,
        vm: &mut EbpfVm<C>,
    ) {
        arch::enter(executable, Some(self), vm)
    }
}

impl<C: ContextObject> Executable<C> {
    /// Compile the executable with the parrot JIT.
    ///
    /// The result is stored (and can be retrieved, executed and taken) exactly like the output of
    /// [`Self::jit_compile`]. sBPF versions that parrot does not support are compiled with
    /// `jit_compile` instead, if it is available.
    pub fn parrot_compile(&self) -> Result<(), EbpfError> {
        let version = self.get_sbpf_version();
        if matches!(version, SBPFVersion::V1 | SBPFVersion::V2) {
            return cfg_select! {
                all(feature = "jit", not(target_os = "windows")) => self.jit_compile(),
                _ => Ok(()),
            };
        }
        let compiled = std::sync::Arc::new(jit_templates(version).compile(self)?);
        let mut guard = self
            .compiled_program
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        *guard = Some(compiled);
        Ok(())
    }
}

//! The x86_64 backend.

use super::generate::{Generator, Reg};
use super::{SIG_EXCEEDED_MAX_INSTRUCTIONS, SIG_EXECUTION_OVERRUN};
use crate::ebpf;
use std::convert::TryFrom;

/// The relocations of `dynasm` for x86_64.
pub(super) type Relocation = dynasmrt::x64::X64Relocation;

const RAX: u8 = 0;

const RCX: u8 = 1;

const RDX: u8 = 2;

const RBX: u8 = 3;

const RSI: u8 = 6;

const RDI: u8 = 7;

const R8: u8 = 8;

const R9: u8 = 9;

const R10: u8 = 10;

const R11: u8 = 11;

const R12: u8 = 12;

const R13: u8 = 13;

const R14: u8 = 14;

const R15: u8 = 15;

// Internal registers. Keep in sync with the `.alias`es in `x64asm!`.
const RINSN: u8 = RAX;

const RTEMP: u8 = RCX;

const RMETER: u8 = RDX;

/// Mapping from a numbered eBPF register to an x64 one: r0 = rsi, r1 = rdi, etc.
///
/// Keep in sync with the `.alias`es in `x64asm!`, where `R0`..`R10` name the BPF registers.
const GPREG_MAP: [u8; Reg::COUNT] = [
    RSI, RDI, R8, R9, R10, R11, R12, R13, R14, R15,
    // r10 is read-only and could be special-cased to free up a host register, but instructions
    // using it must not get much slower or larger, as they would become an obvious target for
    // resource exhaustion.
    RBX,
];

impl From<Reg> for u8 {
    /// Machine register for the BPF register.
    fn from(reg: Reg) -> u8 {
        GPREG_MAP[reg.0 as usize]
    }
}

macro_rules! x64asm {
    ($output: expr; $($tts:tt)*) => { x64asm!(@munch {$output; [] []} ; $($tts)*) };
    (@munch {$output:expr; [$($acc:tt)*] [$($curr:tt)*]}) => {{
        #![allow(clippy::neg_multiply, clippy::useless_conversion)]
        dynasm::dynasm!($output
            ; .arch x64
            // BPF registers (see `GPREG_MAP`.)
            ; .alias R0, rsi
            ; .alias R1, rdi
            ; .alias R2, r8
            ; .alias R3, r9
            ; .alias R4, r10
            ; .alias R5, r11
            ; .alias R6, r12
            ; .alias R7, r13
            ; .alias R8, r14
            ; .alias R9, r15
            ; .alias R10, rbx
            // Internal registers.
            ; .alias RINSN, rax
            ; .alias RTEMP, rcx
            ; .alias WTEMP, ecx
            ; .alias RMETER, rdx
            $($acc)* $($curr)*
        )
    }};

    // replace ALU_SRC32(src) operand with either the source register for ALU instructions using
    // source register operand, or an immediate fetch for `_IMM` ALU instructions.
    (@munch {$output:expr; [$($acc:tt)*] [$($curr:tt)*]} ALU_SRC32($src:expr) $($rest:tt)*) => {
        x64asm!(@munch {$output; [ $($acc)* ] [ ; if ($output.opcode().op() & ebpf::BPF_X) == ebpf::BPF_X {
            x64asm!(@munch {$output; [;] [$($curr)*]} Rd($src))
          } else {
            x64asm!(@munch {$output; [;] [$($curr)*]} DWORD REL32_IMM)
          }
        ]} $($rest)*)
    };

    (@munch {$output:expr; [$($acc:tt)*] [$($curr:tt)*]} REL32_IMM $($rest:tt)*) => {
        x64asm!(@munch {$output; [ $($acc)* ] [
            $($curr)* [ DWORD -4i32 + RINSN ] ;; $output.template_reloc(TemplateRelocationKind::InsnOffset, -4, 4, 0, ABSOLUTE_DWORD)
        ]} $($rest)*)
    };

    (@munch {$output:expr; [$($acc:tt)*] [$($curr:tt)*]} REL32_OFF $($rest:tt)*) => {
        x64asm!(@munch {$output; [ $($acc)* ] [
            $($curr)* [ DWORD -6i32 + RINSN ] ;; $output.template_reloc(TemplateRelocationKind::InsnOffset, -6, 4, 0, ABSOLUTE_DWORD)
        ]} $($rest)*)
    };

    (@munch {$output:expr; [$($acc:tt)*] [$($curr:tt)*]} ; $($rest:tt)*) => {{
        x64asm!(@munch {$output; [$($acc)* $($curr)* ;] []} $($rest)*)
    }};
    (@munch {$output:expr; [$($acc:tt)*] [$($curr:tt)*]} $tok:tt $($rest:tt)*) => {{
        x64asm!(@munch {$output; [$($acc)*] [$($curr)* $tok]} $($rest)* )
    }};
}

mod entry;
mod insn;
mod relocation;
pub(super) mod supporting_code;

pub(super) use entry::enter;
use entry::Frame;
pub(super) use insn::{
    aux_template, bpf_insn, interpreter_dispatch, interpreter_taken_branch, jit_taken_branch,
};
pub(super) use relocation::{
    TemplateRelocation, TemplateRelocationKind, MAX_JIT_TEMPLATE_SIZE, MAX_RELOCATIONS,
};
pub(super) use supporting_code::interpreter_global;
use supporting_code::SupportingCode;

/// The interpreter steps are 128 bytes.
pub(super) const INTERPRETER_STEP_SIZE_LOG2: u8 = 7;

/// `int3`, to fill the unused space of the interpreter steps.
pub(super) const TRAP_FILL: u8 = 0xcc;

/// The encoding of an absolute 32-bit relocation, for `Generator::template_reloc`.
const ABSOLUTE_DWORD: u8 = 0xc2;

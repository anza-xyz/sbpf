//! The RV64IM backend for Parrot.

use super::generate::{Generator, Reg};
use crate::ebpf;
use std::convert::TryFrom;

/// The relocations emitted by the RISC-V assembler.
pub(super) type Relocation = dynasmrt::riscv::RiscvRelocation;

// Register numbers for dynamically selected operands in `rv_asm!`.
const R10: u8 = 27;
const RINSN: u8 = 5;
const RTEMP: u8 = 6;
const RFIELD: u8 = 31;

// Keep guest registers in s1..s11 across calls into the host.
const GPREG_MAP: [u8; Reg::COUNT] = [9, 18, 19, 20, 21, 22, 23, 24, 25, 26, R10];

impl From<Reg> for u8 {
    fn from(reg: Reg) -> u8 {
        GPREG_MAP[reg.0 as usize]
    }
}

macro_rules! rv_asm {
    ($output:expr; $($tts:tt)*) => {{
        // dynasm casts dynamic shift amounts to the type it already requires.
        #[allow(clippy::unnecessary_cast, clippy::useless_conversion)]
        let () = dynasm::dynasm!($output
            ; .arch riscv64
            ; .feature m
            ; .alias R0, s1
            ; .alias R1, s2
            ; .alias R2, s3
            ; .alias R3, s4
            ; .alias R4, s5
            ; .alias R5, s6
            ; .alias R6, s7
            ; .alias R7, s8
            ; .alias R8, s9
            ; .alias R9, s10
            ; .alias R10, s11
            ; .alias RFRAME, s0
            ; .alias RINSN, t0
            ; .alias RTEMP, t1
            ; .alias RMETER, t2
            ; .alias RCODE, t3
            ; .alias RSUPPORTS, t4
            ; .alias RTARGET, t5
            ; .alias RFIELD, t6
            ; $($tts)*
        );
    }};
}

/// Offset of the `field` of [`Frame`] from `RFRAME`.
macro_rules! frame_offset {
    ($field:ident) => {
        std::mem::offset_of!(crate::codegen::riscv64::entry::Frame, $field) as i32
    };
}

mod entry;
mod insn;
mod relocation;
pub(super) mod supporting_code;

pub(super) use entry::enter;
pub(super) use insn::{
    aux_template, bpf_insn, interpreter_dispatch, interpreter_taken_branch, island,
    jit_taken_branch,
};
pub(super) use relocation::{
    TemplateRelocation, TemplateRelocationKind, MAX_JIT_TEMPLATE_SIZE, MAX_RELOCATIONS,
};
use supporting_code::Support;

/// Map `len` bytes for the interpreter steps.
pub(super) fn map_interpreter(len: usize) -> crate::memory_management::Mapping {
    crate::memory_management::Mapping::pooled(len)
}

/// A fixed-width slot holds a handler and its interpreter dispatch epilogue.
pub(super) const INTERPRETER_STEP_SIZE_LOG2: u8 = 7;

/// All-zero instruction parcels are illegal on RISC-V.
pub(super) const TRAP_FILL: u8 = 0;

/// The JIT output gets an island at most this many bytes apart.
///
/// Templates use JAL to reach islands within 1 MiB. The margin accounts for templates and padding
/// between the start of an island and the next one.
pub(super) const ISLAND_INTERVAL: usize = (1 << 20) - (1 << 12);

/// The entries of an island.
///
/// The templates refer to the entries of the latest island by the global labels of
/// [`Self::of_global`].
#[derive(Clone, Copy, Debug)]
pub(super) enum IslandEntry {
    /// Terminate for an invalid instruction.
    SigInvalidInsn,
    /// Terminate as the instruction meter is exceeded.
    SigMeterExceeded,
    /// Terminate for a division by zero.
    SigDivideByZero,
    /// Where the taken branches continue if their target is out of their reach.
    FarJump,
}

impl IslandEntry {
    pub(super) const COUNT: usize = 4;

    /// The entry that the global label `name` refers to.
    pub(super) fn of_global(name: &str) -> Option<Self> {
        match name {
            "sig_invalid_insn" => Some(Self::SigInvalidInsn),
            "sig_meter_exceeded" => Some(Self::SigMeterExceeded),
            "sig_divide_by_zero" => Some(Self::SigDivideByZero),
            "far_jump" => Some(Self::FarJump),
            _ => None,
        }
    }
}

/// The offsets of the entries from the start of an island.
pub(super) type IslandEntries = [usize; IslandEntry::COUNT];

/// Declare a function or a function pointer type with the ABI of the host functions that the
/// generated code calls.
macro_rules! host_abi {
    (fn ($($args:tt)*) -> $ret:ty) => { extern "C" fn($($args)*) -> $ret };
    ($(#[$attr:meta])* $vis:vis fn $($rest:tt)*) => {
        $(#[$attr])* $vis extern "C" fn $($rest)*
    };
}
pub(super) use host_abi;

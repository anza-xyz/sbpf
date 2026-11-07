//! The aarch64 backend.

use super::generate::{Generator, Reg};
use crate::ebpf;
use std::convert::TryFrom;

/// The relocations of `dynasm` for aarch64.
pub(super) type Relocation = dynasmrt::aarch64::Aarch64Relocation;

// Internal registers. Keep in sync with the `.alias`es in `a64asm!`.
const R10: u8 = 9;

const RINSN: u8 = 10;

const RTEMP: u8 = 11;

/// Scratch for the fields of the BPF instruction.
const RFIELD: u8 = 17;

/// Mapping from a numbered eBPF register to an aarch64 one: r0 = x19, r1 = x20, etc.
///
/// Keep in sync with the `.alias`es in `a64asm!`, where `R0`..`R10` name the BPF registers.
const GPREG_MAP: [u8; Reg::COUNT] = [19, 20, 21, 22, 23, 24, 25, 26, 27, 28, R10];

impl From<Reg> for u8 {
    /// Machine register for the BPF register.
    fn from(reg: Reg) -> u8 {
        GPREG_MAP[reg.0 as usize]
    }
}

macro_rules! a64asm {
    ($output:expr; $($tts:tt)*) => {{
        #[allow(clippy::useless_conversion)]
        let () = dynasm::dynasm!($output
            ; .arch aarch64
            // BPF registers (see `GPREG_MAP`.)
            ; .alias R0, x19
            ; .alias R1, x20
            ; .alias R2, x21
            ; .alias R3, x22
            ; .alias R4, x23
            ; .alias R5, x24
            ; .alias R6, x25
            ; .alias R7, x26
            ; .alias R8, x27
            ; .alias R9, x28
            ; .alias R10, x9
            // Internal registers.
            ; .alias RINSN, x10
            ; .alias RTEMP, x11
            ; .alias WTEMP, w11
            ; .alias RMETER, x12
            // The base address of the code being executed: the interpreter steps or the JIT output.
            ; .alias RCODE, x13
            // The table of the addresses of the supporting functions, see `Support`.
            ; .alias RSUPPORTS, x15
            // The target of the indirect branches.
            ; .alias RTARGET, x16
            ; .alias WTARGET, w16
            ; .alias RFIELD, x17
            ; .alias WFIELD, w17
            // Points at the `Frame`, the start of which is the frame record of the guest code.
            ; .alias RFRAME, x29
            ; $($tts)*
        );
    }};
}

/// Offset of the `field` of [`Frame`] from `RFRAME`.
macro_rules! frame_offset {
    ($field:ident) => {
        std::mem::offset_of!(crate::codegen::aarch64::entry::Frame, $field) as u32
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

/// The interpreter steps are 128 bytes, or 256 with the tracer.
pub(super) const INTERPRETER_STEP_SIZE_LOG2: u8 = if cfg!(feature = "tracer") { 8 } else { 7 };

/// Fills the unused space of the interpreter steps with `udf #0`.
pub(super) const TRAP_FILL: u8 = 0;

/// The JIT output gets an island at most this many bytes apart.
///
/// Conditional branches reach 1 MiB, and the margin accounts for the templates and padding
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
    /// Terminate for a signed division that overflows.
    SigDivideOverflow,
    /// Where the taken branches continue if their target is out of their reach.
    FarJump,
}

impl IslandEntry {
    pub(super) const COUNT: usize = 5;

    /// The entry that the global label `name` refers to.
    pub(super) fn of_global(name: &str) -> Option<Self> {
        match name {
            "sig_invalid_insn" => Some(Self::SigInvalidInsn),
            "sig_meter_exceeded" => Some(Self::SigMeterExceeded),
            "sig_divide_by_zero" => Some(Self::SigDivideByZero),
            "sig_divide_overflow" => Some(Self::SigDivideOverflow),
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

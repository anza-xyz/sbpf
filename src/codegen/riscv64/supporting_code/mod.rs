//! Code shared by the JIT and the interpreters of all SBPF versions, generated once into its own
//! executable memory.
//!
//! The generated code loads the addresses of the supporting functions from a table that
//! `RSUPPORTS` points at (see [`Support`]).

use super::*;
use crate::codegen::generate::InterpreterGenerator;
use crate::codegen::host::{self, AccessSize, HostCallStatus};
use crate::codegen::templates::JitTemplates;
use crate::codegen::{
    SIG_CALL_DEPTH_EXCEEDED, SIG_CALL_OUTSIDE_TEXT_SEGMENT, SIG_DIVIDE_BY_ZERO,
    SIG_EXCEEDED_MAX_INSTRUCTIONS, SIG_EXECUTION_OVERRUN, SIG_INVALID_INSN, SIG_PROGRAM_RESULT,
};
use crate::memory_management::{Mapping, ReadExecute};
use dynasmrt::{DynasmApi, DynasmLabelApi, VecAssembler};
use std::sync::LazyLock;

mod memory;

pub(super) type Asm = VecAssembler<Relocation>;

/// A supporting function, by its slot in [`SupportingCode::table`].
///
/// All of them expect `RTEMP` to contain the address of the next BPF instruction (cf.
/// `load_next_insn_addr`), except for the signal `SIG_EXCEEDED_MAX_INSTRUCTIONS`.
#[derive(Clone, Copy)]
pub(super) enum Support {
    /// Terminate the execution with the signal. These are jumped to rather than called.
    Signal(i8),
    /// `CALL_IMM` SBPFv3 onwards.
    CallImm,
    /// Syscall trampoline.
    Syscall,
    /// Continue a taken branch whose target is outside the range of its JAL instruction.
    FarJump,
    /// SBPFv0 `CALL_IMM`.
    V0CallImm,
    /// SBPFv0 `CALL_REG`.
    V0Callx,
    /// Trace the current registers and the PC of the instruction immediately before `RTEMP`.
    #[cfg(feature = "tracer")]
    Trace,
    /// `CALL_REG` SBPFv3 onwards, with the callee in `a0`.
    Callx,
    /// Load into `a0` from the address in `a1` plus the offset.
    Load(AccessSize),
    /// Store the immediate to the address in `a1` plus the offset.
    StoreImm(AccessSize),
    /// Store `a2` to the address in `a1` plus the offset.
    StoreReg(AccessSize),
}

/// The signals of [`Support::Signal`], in the order of their slots.
const SIGNALS: [i8; 4] = [
    SIG_EXCEEDED_MAX_INSTRUCTIONS,
    SIG_INVALID_INSN,
    SIG_DIVIDE_BY_ZERO,
    SIG_EXECUTION_OVERRUN,
];

impl Support {
    const LOAD: usize = SIGNALS.len() + 7;
    const STORE_IMM: usize = Self::LOAD + AccessSize::ALL.len();
    const STORE_REG: usize = Self::STORE_IMM + AccessSize::ALL.len();
    pub(super) const COUNT: usize = Self::STORE_REG + AccessSize::ALL.len();

    fn slot(self) -> usize {
        let fixed = SIGNALS.len();
        match self {
            Self::Signal(signal) => SIGNALS
                .iter()
                .position(|&s| s == signal)
                .expect("no slot for the signal"),
            Self::CallImm => fixed,
            Self::Syscall => fixed.wrapping_add(1),
            Self::V0CallImm => fixed.wrapping_add(2),
            Self::V0Callx => fixed.wrapping_add(3),
            #[cfg(feature = "tracer")]
            Self::Trace => fixed.wrapping_add(4),
            Self::FarJump => fixed.wrapping_add(5),
            Self::Callx => fixed.wrapping_add(6),
            Self::Load(size) => Self::LOAD.wrapping_add(size as usize),
            Self::StoreImm(size) => Self::STORE_IMM.wrapping_add(size as usize),
            Self::StoreReg(size) => Self::STORE_REG.wrapping_add(size as usize),
        }
    }

    /// Offset of the address of the function from `RSUPPORTS`.
    pub(super) fn table_offset(self) -> i32 {
        i32::try_from(self.slot().wrapping_mul(8)).unwrap()
    }
}

pub(in crate::codegen) struct SupportingCode {
    /// The entrypoint to set up the machine state VM execution expects.
    pub(super) entry_point: usize,
    /// The addresses of the functions, see [`Support`].
    pub(super) table: [usize; Support::COUNT],
    /// Keeps the code mapped.
    _code: Mapping<ReadExecute>,
}

static SUPPORTING_CODE: LazyLock<SupportingCode> = LazyLock::new(SupportingCode::generate);

impl SupportingCode {
    pub(in crate::codegen) fn get() -> &'static SupportingCode {
        &SUPPORTING_CODE
    }

    fn generate() -> SupportingCode {
        let mut out = Asm::new(0);
        // Offsets in `out` until the code is placed.
        let mut table = [0; Support::COUNT];
        let mut set = |support: Support, offset: usize| table[support.slot()] = offset;
        for (signal, offset) in SIGNALS.iter().copied().zip(signals(&mut out)) {
            set(Support::Signal(signal), offset);
        }
        set(Support::CallImm, call_imm(&mut out));
        set(Support::Syscall, syscall(&mut out));
        set(Support::FarJump, far_jump(&mut out));
        set(Support::V0CallImm, v0_call_imm(&mut out));
        let (v0_callx, callx) = callx(&mut out);
        set(Support::V0Callx, v0_callx);
        set(Support::Callx, callx);
        #[cfg(feature = "tracer")]
        set(Support::Trace, trace(&mut out));
        memory::generate(&mut out, &mut set);
        let entry_point = entry::entry_point(&mut out);
        let code = out
            .finalize()
            .expect("failed to resolve the supporting code");
        let mut mapping = Mapping::pooled(code.len());
        mapping[..code.len()].copy_from_slice(&code);
        let mapping = mapping.protect::<ReadExecute>();
        let base = mapping.as_ptr() as usize;
        Self {
            entry_point: base.wrapping_add(entry_point),
            table: table.map(|offset| base.wrapping_add(offset)),
            _code: mapping,
        }
    }
}

/// Keep the machine-code entry points 16-byte aligned.
pub(super) fn function_start(out: &mut Asm) -> usize {
    rv_asm!(out; .align 16);
    out.offset().0
}

fn terminate(out: &mut Asm, code: i8) {
    if code == SIG_EXCEEDED_MAX_INSTRUCTIONS {
        // The first instruction past the budget may precede the instruction that checked it.
        rv_asm!(out; addi RTEMP, RMETER, ebpf::INSN_SIZE as i32);
    } else {
        rv_asm!(out; sub RMETER, RMETER, RTEMP);
    }
    rv_asm!(out
        ; addi a0, zero, i32::from(code)
        ; j ->exit
    );
}

fn validate_meter(out: &mut Asm) {
    // The signal can be farther away than a B-type conditional branch reaches.
    let available = out.new_dynamic_label();
    rv_asm!(out
        ; bgeu RMETER, RTEMP, =>available
        ; j ->sig_meter_exceeded
        ; =>available
    );
}

fn signals(out: &mut Asm) -> [usize; SIGNALS.len()] {
    SIGNALS.map(|signal| {
        let start = function_start(out);
        if signal == SIG_EXCEEDED_MAX_INSTRUCTIONS {
            rv_asm!(out; ->sig_meter_exceeded:);
        } else {
            validate_meter(out);
        }
        terminate(out, signal);
        start
    })
}

/// The first two words of the spill area are the host's mutable MeterSlots.
fn push_for_host_call(out: &mut Asm) {
    rv_asm!(out
        ; addi sp, sp, -32
        ; sd RMETER, [sp]
        ; sd RTEMP, [sp, 8]
        ; sd RINSN, [sp, 16]
        ; sd ra, [sp, 24]
    );
}

fn pop_after_host_call(out: &mut Asm) {
    rv_asm!(out
        ; ld RMETER, [sp]
        ; ld RTEMP, [sp, 8]
        ; ld RINSN, [sp, 16]
        ; ld ra, [sp, 24]
        ; addi sp, sp, 32
        ; ld RCODE, [RFRAME, frame_offset!(code)]
        ; ld RSUPPORTS, [RFRAME, frame_offset!(supports)]
    );
}

/// A direct CALL_IMM has already checked its target offset. CALL_REG and V0 calls provide
/// absolute host addresses that need a bounds check before indexing the pc or dispatch table.
#[derive(PartialEq)]
enum Callee {
    AbsoluteAddress,
    CheckedOffset,
}

/// Enter the BPF callee in RTARGET after checking the caller's meter.
fn internal_call(out: &mut Asm, callee: Callee) {
    let step_shift = u32::from(InterpreterGenerator::STEP_SIZE_LOG2);
    let [outside, too_deep, interpreted, resolved] = [(); 4].map(|()| out.new_dynamic_label());
    if callee == Callee::AbsoluteAddress {
        rv_asm!(out
            ; ld RFIELD, [RFRAME, frame_offset!(text_section)]
            ; sub RTARGET, RTARGET, RFIELD
            ; ld RFIELD, [RFRAME, frame_offset!(text_section_len)]
            ; bgeu RTARGET, RFIELD, =>outside
            ; andi RTARGET, RTARGET, (ebpf::INSN_SIZE as i32).wrapping_neg()
        );
    }
    rv_asm!(out
        ; ld RFIELD, [RFRAME, frame_offset!(calls_remaining)]
        ; sltiu a0, RFIELD, 2
        ; bnez a0, =>too_deep
        ; addi RFIELD, RFIELD, -1
        ; sd RFIELD, [RFRAME, frame_offset!(calls_remaining)]

        ; addi sp, sp, -64
        ; sd ra, [sp]
        ; sd RTEMP, [sp, 8]
        ; sd RINSN, [sp, 16]
        ; sd R10, [sp, 24]
        ; sd R6, [sp, 32]
        ; sd R7, [sp, 40]
        ; sd R8, [sp, 48]
        ; sd R9, [sp, 56]
        ; ld RFIELD, [RFRAME, frame_offset!(text_section)]
        ; add RFIELD, RFIELD, RTARGET
        ; add RMETER, RMETER, RFIELD
        ; sub RMETER, RMETER, RTEMP
        ; ld a0, [RFRAME, frame_offset!(jit_pc_section)]
        ; beqz a0, =>interpreted
        // An 8-byte guest slot has a 4-byte native pc-table entry.
        ; srli RTARGET, RTARGET, 1
        ; add RTARGET, a0, RTARGET
        ; lwu RTARGET, [RTARGET]
        ; add RTARGET, RCODE, RTARGET
        ; addi RFIELD, RFIELD, ebpf::INSN_SIZE as i32
        ; sd RFIELD, [RFRAME, frame_offset!(next_insn)]
        ; j =>resolved
        ; =>interpreted
        ; lhu RTARGET, [RFIELD]
        ; slli RTARGET, RTARGET, step_shift
        ; add RTARGET, RCODE, RTARGET
        ; addi RINSN, RFIELD, ebpf::INSN_SIZE as i32
        ; =>resolved
        ; ld RFIELD, [RFRAME, frame_offset!(stack_frame_bump)]
        ; add R10, R10, RFIELD
        ; jal ra, ->call_bpf
        ; ld ra, [sp]
        ; ld RTEMP, [sp, 8]
        ; ld RINSN, [sp, 16]
        ; ld R10, [sp, 24]
        ; ld R6, [sp, 32]
        ; ld R7, [sp, 40]
        ; ld R8, [sp, 48]
        ; ld R9, [sp, 56]
        ; addi sp, sp, 64
        ; add RMETER, RMETER, RTEMP
        ; ld RFIELD, [RFRAME, frame_offset!(calls_remaining)]
        ; addi RFIELD, RFIELD, 1
        ; sd RFIELD, [RFRAME, frame_offset!(calls_remaining)]
        ; ret
        ; =>outside
        ;; terminate(out, SIG_CALL_OUTSIDE_TEXT_SEGMENT)
        ; =>too_deep
        ;; terminate(out, SIG_CALL_DEPTH_EXCEEDED)
    );
}

/// Far branch using the program's pc table. The instruction template adjusted the meter.
fn far_jump(out: &mut Asm) -> usize {
    let start = function_start(out);
    let [invalid, resolved] = [(); 2].map(|()| out.new_dynamic_label());
    rv_asm!(out
        ; lh RFIELD, [RTEMP, -6]
        ; slli RFIELD, RFIELD, 3
        ; add RFIELD, RFIELD, RTEMP
        ; ld a0, [RFRAME, frame_offset!(text_section)]
        ; sub RFIELD, RFIELD, a0
        ; ld a0, [RFRAME, frame_offset!(text_section_len)]
        ; bgeu RFIELD, a0, =>invalid
        ; srli RFIELD, RFIELD, 1
        ; ld a0, [RFRAME, frame_offset!(jit_pc_section)]
        ; add RFIELD, RFIELD, a0
        ; lwu RFIELD, [RFIELD]
        ; =>resolved
        ; add RTARGET, RCODE, RFIELD
        ; jr RTARGET
        ; =>invalid
        ; addi RFIELD, zero, JitTemplates::<0>::INVALID_CALL_TARGET as i32
        ; j =>resolved
    );
    start
}

fn call_imm(out: &mut Asm) -> usize {
    let start = function_start(out);
    let invalid = out.new_dynamic_label();
    validate_meter(out);
    rv_asm!(out
        ; lw RTARGET, [RTEMP, -4]
        ; slli RTARGET, RTARGET, 3
        ; add RTARGET, RTEMP, RTARGET
        ; ld RFIELD, [RFRAME, frame_offset!(text_section)]
        ; sub RTARGET, RTARGET, RFIELD
        ; ld RFIELD, [RFRAME, frame_offset!(text_section_len)]
        ; bgeu RTARGET, RFIELD, =>invalid
        ;; internal_call(out, Callee::CheckedOffset)
        ; =>invalid
        ;; terminate(out, SIG_INVALID_INSN)
    );
    start
}

fn callx(out: &mut Asm) -> (usize, usize) {
    let [common, stubs, invalid] = [(); 3].map(|()| out.new_dynamic_label());
    let callx = function_start(out);
    rv_asm!(out
        ; =>common
        ;; validate_meter(out)
        ; ld RFIELD, [RFRAME, frame_offset!(text_section_host_to_vm)]
        ; sub RTARGET, a0, RFIELD
        ;; internal_call(out, Callee::AbsoluteAddress)
    );

    // V0 stores a register number in the immediate. Each stub moves that register to a0.
    let v0_callx = function_start(out);
    rv_asm!(out
        ; lwu a0, [RTEMP, -4]
        ; sltiu RFIELD, a0, Reg::COUNT as i32
        ; beqz RFIELD, =>invalid
        ; la RTARGET, =>stubs
        ; slli a0, a0, 3
        ; add RTARGET, RTARGET, a0
        ; jr RTARGET
        ; =>invalid
        ;; validate_meter(out)
        ;; terminate(out, SIG_INVALID_INSN)
        ; =>stubs
    );
    for reg in Reg::ALL {
        let at = out.offset().0;
        rv_asm!(out
            ; mv a0, X(u8::from(reg))
            ; j =>common
        );
        assert_eq!(out.offset().0.checked_sub(at).unwrap(), 8);
    }
    (v0_callx, callx)
}

/// Synchronize the syscall-visible registers with the VM, then call its dispatcher. The C ABI
/// returns HostCallResult in a0 and the low byte of a1.
fn call_dispatcher(out: &mut Asm) {
    push_for_host_call(out);
    rv_asm!(out; ld a0, [RFRAME, frame_offset!(vm)]);
    for reg in &Reg::ALL[..6] {
        rv_asm!(out; sd X(u8::from(*reg)), [a0, host::register_slot(*reg) as i32]);
    }
    rv_asm!(out
        // RV64 sign-extends 32-bit C ABI arguments, including unsigned ones.
        ; lw a1, [RTEMP, -4]
        ; sub a2, RMETER, RTEMP
        ; srli a2, a2, 3
        ; ld a3, [RFRAME, frame_offset!(function_registry)]
        ; ld RTARGET, [RFRAME, frame_offset!(call_dispatcher)]
        ; jalr RTARGET
        ; andi a1, a1, 255
        ;; pop_after_host_call(out)
        ; ld RFIELD, [RFRAME, frame_offset!(vm)]
    );
    for reg in &Reg::ALL[..6] {
        rv_asm!(out; ld X(u8::from(*reg)), [RFIELD, host::register_slot(*reg) as i32]);
    }
}

fn v0_call_imm(out: &mut Asm) -> usize {
    let start = function_start(out);
    let not_internal = out.new_dynamic_label();
    validate_meter(out);
    call_dispatcher(out);
    rv_asm!(out
        ; addi RFIELD, zero, HostCallStatus::CallInternal as i32
        ; bne a1, RFIELD, =>not_internal
        ; ld RFIELD, [RFRAME, frame_offset!(text_section)]
        ; slli RTARGET, a0, 3
        ; add RTARGET, RFIELD, RTARGET
        ;; internal_call(out, Callee::AbsoluteAddress)
        ; =>not_internal
    );
    syscall_result(out);
    start
}

fn syscall(out: &mut Asm) -> usize {
    let start = function_start(out);
    validate_meter(out);
    call_dispatcher(out);
    syscall_result(out);
    start
}

fn syscall_result(out: &mut Asm) {
    let failed = out.new_dynamic_label();
    rv_asm!(out
        ; slli RMETER, a0, 3
        ; add RMETER, RTEMP, RMETER
        ; bnez a1, =>failed
        ; ret
        ; =>failed
        ;; terminate(out, SIG_PROGRAM_RESULT)
    );
}

#[cfg(feature = "tracer")]
fn trace(out: &mut Asm) -> usize {
    let start = function_start(out);
    push_for_host_call(out);
    rv_asm!(out; ld a0, [RFRAME, frame_offset!(vm)]);
    for reg in Reg::ALL {
        rv_asm!(out; sd X(u8::from(reg)), [a0, host::register_slot(reg) as i32]);
    }
    rv_asm!(out
        ; ld RFIELD, [RFRAME, frame_offset!(text_section)]
        ; sub RFIELD, RTEMP, RFIELD
        ; srli RFIELD, RFIELD, 3
        ; addi RFIELD, RFIELD, -1
        ; sd RFIELD, [a0, host::PC_SLOT as i32]
        ; ld RTARGET, [RFRAME, frame_offset!(trace)]
        ; jalr RTARGET
        ;; pop_after_host_call(out)
        ; ret
    );
    start
}

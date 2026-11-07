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
    /// Continue at the target of the taken branch that jumped here, which is out of its reach.
    /// Jumped to rather than called.
    FarJump,
    /// SBPFv0 `CALL_IMM`.
    V0CallImm,
    /// SBPFv0 `CALL_REG`.
    V0Callx,
    /// Append registers and the pc at `RTEMP` to `vm.register_trace`.
    #[cfg(feature = "tracer")]
    Trace,
    /// `CALL_REG` SBPFv3 onwards, with the callee in `x0`.
    Callx,
    /// Load into `x0` from the address in `x1` plus the offset.
    Load(AccessSize),
    /// Store the immediate to the address in `x1` plus the offset.
    StoreImm(AccessSize),
    /// Store `x2` to the address in `x1` plus the offset.
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
    pub(super) fn table_offset(self) -> u32 {
        u32::try_from(self.slot().wrapping_mul(8)).unwrap()
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

/// Where the code of the next supporting function in `out` starts.
pub(super) fn function_start(out: &mut Asm) -> usize {
    a64asm!(out; .align FUNCTION_ALIGNMENT);
    out.offset().0
}

/// The supporting functions are aligned to this, like the compilers do.
const FUNCTION_ALIGNMENT: usize = 16;

/// Terminate the execution with `code`.
fn terminate(out: &mut Asm, code: i8) {
    if code == SIG_EXCEEDED_MAX_INSTRUCTIONS {
        // The faulting instruction is the one at the limit rather than the one where the meter was
        // checked.
        a64asm!(out; add RTEMP, RMETER, ebpf::INSN_SIZE as u32);
    } else {
        a64asm!(out; sub RMETER, RMETER, RTEMP);
    }
    a64asm!(out
        ; movz w0, u32::from(code as u8)
        ; b ->exit
    );
}

/// Terminate the execution if the instruction budget has been exceeded.
fn validate_meter(out: &mut Asm) {
    a64asm!(out
        ; cmp RTEMP, RMETER
        ; b.hi ->sig_meter_exceeded
    );
}

/// The supporting functions for [`SIGNALS`].
fn signals(out: &mut Asm) -> [usize; SIGNALS.len()] {
    SIGNALS.map(|signal| {
        let start = function_start(out);
        if signal == SIG_EXCEEDED_MAX_INSTRUCTIONS {
            a64asm!(out; ->sig_meter_exceeded:);
        } else {
            // Running out of budget takes precedence.
            validate_meter(out);
        }
        terminate(out, signal);
        start
    })
}

/// Where [`push_for_host_call`] leaves `RMETER` and `RTEMP`, in the layout of
/// [`host::MeterSlots`], relative to `sp`.
const METER_SLOTS: u32 = 0;

/// Push the internal registers that a host function call would clobber.
fn push_for_host_call(out: &mut Asm) {
    // `RCODE` and `RSUPPORTS` are reloaded from the `Frame` instead.
    a64asm!(out
        ; stp RMETER, RTEMP, [sp, -48]!
        ; stp x30, R10, [sp, 16]
        ; str RINSN, [sp, 32]
    );
    const { assert!(METER_SLOTS == 0) };
}

/// Undo [`push_for_host_call`].
fn pop_after_host_call(out: &mut Asm) {
    a64asm!(out
        ; ldr RINSN, [sp, 32]
        ; ldp x30, R10, [sp, 16]
        ; ldp RMETER, RTEMP, [sp], 48
        ; ldr RCODE, [RFRAME, frame_offset!(code)]
        ; ldr RSUPPORTS, [RFRAME, frame_offset!(supports)]
    );
}

/// Call the BPF function at `RTARGET`.
///
/// The return address goes on the stack, for `EXIT` to pop, as the function does not preserve
/// `x30`. Uses `x0` as a scratch.
pub(super) fn call_bpf_function(out: &mut Asm) {
    let returned = out.new_dynamic_label();
    a64asm!(out
        ; adr x0, =>returned
        ; str x0, [sp, -16]!
        ; blr RTARGET
        ; =>returned
    );
}

/// Store BPF registers r0 to r5, which are the ones the syscalls may read and write, into
/// [`EbpfVm::registers`](crate::vm::EbpfVm::registers).
///
/// Leaves the `EbpfVm` in `x0`.
fn store_syscall_registers(out: &mut Asm) {
    a64asm!(out
        ; ldr x0, [RFRAME, frame_offset!(vm)]
        ; add x4, x0, host::register_slot(Reg(0)) as u32
        ; stp R0, R1, [x4]
        ; stp R2, R3, [x4, 16]
        ; stp R4, R5, [x4, 32]
    );
}

/// Undo [`store_syscall_registers`]. Leaves `x0` and `x1` as they are.
fn load_syscall_registers(out: &mut Asm) {
    a64asm!(out
        ; ldr RFIELD, [RFRAME, frame_offset!(vm)]
        ; add RFIELD, RFIELD, host::register_slot(Reg(0)) as u32
        ; ldp R0, R1, [RFIELD]
        ; ldp R2, R3, [RFIELD, 16]
        ; ldp R4, R5, [RFIELD, 32]
    );
}

/// How the callee of [`internal_call`] is given in `RTARGET`.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Callee {
    /// Absolute address, not yet known to be within the text section.
    AbsoluteAddress,
    /// The relative offset in the text section, known to be within it.
    CheckedOffset,
}

/// Call the BPF function given in `RTARGET`.
///
/// The meter must have been validated already.
fn internal_call(out: &mut Asm, callee: Callee) {
    let [outside, too_deep, interpreted, resolved] = [(); 4].map(|()| out.new_dynamic_label());
    if callee == Callee::AbsoluteAddress {
        a64asm!(out
            ; ldr RFIELD, [RFRAME, frame_offset!(text_section)]
            ; sub RTARGET, RTARGET, RFIELD
            ; ldr RFIELD, [RFRAME, frame_offset!(text_section_len)]
            ; cmp RTARGET, RFIELD
            ; b.hs =>outside
            ; and RTARGET, RTARGET, (ebpf::INSN_SIZE as u64).wrapping_neg()
        );
    }
    a64asm!(out
        ; ldr RFIELD, [RFRAME, frame_offset!(calls_remaining)]
        ; subs RFIELD, RFIELD, 1
        // `ls` rather than `eq`, to also catch `calls_remaining` having been 0.
        ; b.ls =>too_deep
        ; str RFIELD, [RFRAME, frame_offset!(calls_remaining)]

        // `RTEMP` for converting the meter back once the callee returns.
        ; stp x30, RTEMP, [sp, -64]!
        ; str RINSN, [sp, 16]
        ; stp R6, R7, [sp, 32]
        ; stp R8, R9, [sp, 48]
        ; ldr RFIELD, [RFRAME, frame_offset!(text_section)]
        ; add RFIELD, RFIELD, RTARGET
        // Meter adjustments mirror the logic of the taken branch instruction.
        ; add RMETER, RMETER, RFIELD
        ; sub RMETER, RMETER, RTEMP
        ; ldr x0, [RFRAME, frame_offset!(jit_pc_section)]
        ; cbz x0, =>interpreted

        ; lsr RTARGET, RTARGET, 1
        ; ldr WTARGET, [x0, RTARGET]
        ; add RTARGET, RCODE, RTARGET
        ; add RFIELD, RFIELD, ebpf::INSN_SIZE as u32
        ; str RFIELD, [RFRAME, frame_offset!(next_insn)]
        ; b =>resolved

        ; =>interpreted
        ; ldrh WTARGET, [RFIELD]
        ; add RTARGET, RCODE, RTARGET, lsl InterpreterGenerator::STEP_SIZE_LOG2 as u32
        ; add RINSN, RFIELD, ebpf::INSN_SIZE as u32

        ; =>resolved
        ; ldr RFIELD, [RFRAME, frame_offset!(stack_frame_bump)]
        ; add R10, R10, RFIELD
        ;; call_bpf_function(out)
        ; ldr RFIELD, [RFRAME, frame_offset!(stack_frame_bump)]
        ; sub R10, R10, RFIELD
        ; ldp R8, R9, [sp, 48]
        ; ldp R6, R7, [sp, 32]
        ; ldr RINSN, [sp, 16]
        ; ldp x30, RTEMP, [sp], 64
        // `EXIT` left the remaining budget in `RMETER`, convert back to the instruction limit.
        ; add RMETER, RMETER, RTEMP
        ; ldr RFIELD, [RFRAME, frame_offset!(calls_remaining)]
        ; add RFIELD, RFIELD, 1
        ; str RFIELD, [RFRAME, frame_offset!(calls_remaining)]
        ; ret

        ; =>outside
        ;; terminate(out, SIG_CALL_OUTSIDE_TEXT_SEGMENT)

        ; =>too_deep
        ;; terminate(out, SIG_CALL_DEPTH_EXCEEDED)
    );
}

/// See [`Support::FarJump`]. Expects `RTEMP` to hold the address of the instruction following the
/// branch, and the meter to be adjusted for the branch already.
fn far_jump(out: &mut Asm) -> usize {
    let start = function_start(out);
    let [invalid, resolved] = [(); 2].map(|()| out.new_dynamic_label());
    a64asm!(out
        ; ldursh RFIELD, [RTEMP, -6]
        ; add RFIELD, RTEMP, RFIELD, lsl 3
        ; ldr x0, [RFRAME, frame_offset!(text_section)]
        ; sub RFIELD, RFIELD, x0
        // The verifier rejects invalid jump offsets, but checking them is cheap.
        ; ldr x0, [RFRAME, frame_offset!(text_section_len)]
        ; cmp RFIELD, x0
        ; b.hs =>invalid
        ; lsr RFIELD, RFIELD, 1
        ; ldr x0, [RFRAME, frame_offset!(jit_pc_section)]
        ; ldr WFIELD, [x0, RFIELD]
        ; =>resolved
        ; add RTARGET, RCODE, RFIELD
        ; br RTARGET
        ; =>invalid
        ; movz RFIELD, JitTemplates::<0>::INVALID_CALL_TARGET
        ; b =>resolved
    );
    start
}

fn call_imm(out: &mut Asm) -> usize {
    let start = function_start(out);
    let invalid = out.new_dynamic_label();
    validate_meter(out);
    a64asm!(out
        ; ldursw RTARGET, [RTEMP, -4]
        ; add RTARGET, RTEMP, RTARGET, lsl 3
        ; ldr RFIELD, [RFRAME, frame_offset!(text_section)]
        ; sub RTARGET, RTARGET, RFIELD
        ; ldr RFIELD, [RFRAME, frame_offset!(text_section_len)]
        ; cmp RTARGET, RFIELD
        ; b.hs =>invalid
        ;; internal_call(out, Callee::CheckedOffset)

        ; =>invalid
        ;; terminate(out, SIG_INVALID_INSN)
    );
    start
}

/// Returns the SBPFv0 `CALL_REG` and the SBPFv3 ones for each register.
fn callx(out: &mut Asm) -> (usize, usize) {
    const STUB_SIZE: usize = 8;
    let [common, stubs, invalid] = [(); 3].map(|()| out.new_dynamic_label());
    let callx = function_start(out);
    a64asm!(out
        ; =>common
        ;; validate_meter(out)
        ; ldr RFIELD, [RFRAME, frame_offset!(text_section_host_to_vm)]
        ; sub RTARGET, x0, RFIELD
        ;; internal_call(out, Callee::AbsoluteAddress)
    );

    // v0 stores the register in the immediate field, which selects one of the stubs that move it
    // into `x0`.
    let v0_callx = function_start(out);
    let last_register = u32::try_from(GPREG_MAP.len())
        .unwrap()
        .checked_sub(1)
        .unwrap();
    a64asm!(out
        ; ldur w0, [RTEMP, -4]
        ; cmp w0, last_register
        ; b.hi =>invalid
        ; adr RTARGET, =>stubs
        ; add RTARGET, RTARGET, x0, lsl STUB_SIZE.trailing_zeros()
        ; br RTARGET

        ; =>invalid
        ;; validate_meter(out)
        ;; terminate(out, SIG_INVALID_INSN)
        ; =>stubs
    );
    for reg in Reg::ALL {
        let stub_start = out.offset().0;
        a64asm!(out
            ; mov x0, X(u8::from(reg))
            ; b =>common
        );
        assert_eq!(out.offset().0.checked_sub(stub_start).unwrap(), STUB_SIZE);
    }
    (v0_callx, callx)
}

/// Call the [`Frame::call_dispatcher`] with `vm`, the immediate and the remaining budget as the
/// first three arguments, `extra` setting up the rest of them.
///
/// Leaves the result in `x0` and `w1`.
fn call_dispatcher(out: &mut Asm, extra: impl FnOnce(&mut Asm)) {
    push_for_host_call(out);
    store_syscall_registers(out);
    a64asm!(out
        ; ldur w1, [RTEMP, -4]
        ; sub x2, RMETER, RTEMP
        ; lsr x2, x2, 3
        ;; extra(out)
        ; ldr RTARGET, [RFRAME, frame_offset!(call_dispatcher)]
        ; blr RTARGET
        ; and w1, w1, 0xff
        ;; pop_after_host_call(out)
        ;; load_syscall_registers(out)
    );
}

fn v0_call_imm(out: &mut Asm) -> usize {
    let start = function_start(out);
    let [not_internal, failed] = [(); 2].map(|()| out.new_dynamic_label());
    validate_meter(out);
    call_dispatcher(out, |out| {
        a64asm!(out; ldr x3, [RFRAME, frame_offset!(function_registry)]);
    });
    a64asm!(out
        ; cmp w1, HostCallStatus::CallInternal as u32
        ; b.ne =>not_internal
        ; ldr RFIELD, [RFRAME, frame_offset!(text_section)]
        ; add RTARGET, RFIELD, x0, lsl 3
        ;; internal_call(out, Callee::AbsoluteAddress)

        // The syscall consumes the meter even if it failed.
        ; =>not_internal
        ; add RMETER, RTEMP, x0, lsl 3
        ; cbnz w1, =>failed
        ; ret

        ; =>failed
        ;; terminate(out, SIG_PROGRAM_RESULT)
    );
    start
}

fn syscall(out: &mut Asm) -> usize {
    let start = function_start(out);
    let failed = out.new_dynamic_label();
    validate_meter(out);
    call_dispatcher(out, |_| {});
    a64asm!(out
        // The syscall consumes the meter even if it failed.
        ; add RMETER, RTEMP, x0, lsl 3
        ; cbnz w1, =>failed
        ; ret

        ; =>failed
        ;; terminate(out, SIG_PROGRAM_RESULT)
    );
    start
}

#[cfg(feature = "tracer")]
fn trace(out: &mut Asm) -> usize {
    let start = function_start(out);
    let function = host::push_register_trace as *const u8 as u64;
    push_for_host_call(out);
    a64asm!(out
        ; ldr x0, [RFRAME, frame_offset!(vm)]
        ; add x4, x0, host::register_slot(Reg(0)) as u32
        ; stp R0, R1, [x4]
        ; stp R2, R3, [x4, 16]
        ; stp R4, R5, [x4, 32]
        ; stp R6, R7, [x4, 48]
        ; stp R8, R9, [x4, 64]
        ; ldr RFIELD, [RFRAME, frame_offset!(text_section)]
        ; sub RFIELD, RTEMP, RFIELD
        ; lsr RFIELD, RFIELD, 3
        ; sub RFIELD, RFIELD, 1
        ; stp R10, RFIELD, [x4, 80]
        ; movz RTARGET, (function & 0xffff) as u32
        ; movk RTARGET, (function >> 16 & 0xffff) as u32, lsl 16
        ; movk RTARGET, (function >> 32 & 0xffff) as u32, lsl 32
        ; movk RTARGET, (function >> 48) as u32, lsl 48
        ; blr RTARGET
        ;; pop_after_host_call(out)
        ; ret
    );
    const { assert!(host::PC_SLOT == host::register_slot(Reg(0)) + 88) };
    start
}

//! Code shared by the JIT and the interpreters of all SBPF versions.
//!
//! It is generated once, and a copy of it is placed within reach of a relative `call` from the code
//! calling it: once after the interpreter steps, and every [`SUPPORTS_INTERVAL`] bytes in the JIT
//! output. A relative `call` is predicted much better than an indirect one through a register.
//!
//! The supporting code is self-contained: unlike the templates it does not use the islands, which
//! may be placed much more frequently than the supporting code is.

use super::*;
use crate::codegen::generate::InterpreterGenerator;
use crate::codegen::{
    SIG_CALL_DEPTH_EXCEEDED, SIG_CALL_OUTSIDE_TEXT_SEGMENT, SIG_DIVIDE_BY_ZERO,
    SIG_DIVIDE_OVERFLOW, SIG_INVALID_INSN, SIG_PROGRAM_RESULT,
};
use crate::program::SBPFVersion;
use crate::vm::EbpfVm;
use dynasmrt::x64::X64Relocation;
use dynasmrt::{DynamicLabel, DynasmApi, DynasmLabelApi, VecAssembler};
use std::sync::LazyLock;

/// The supporting code, see the module documentation.
pub(in crate::codegen) struct SupportingCode {
    /// Position independent machine code, to be placed at a [`SUPPORTS_ALIGNMENT`] aligned
    /// address.
    pub(in crate::codegen) code: Box<[u8]>,
    /// The offset of each [`SupportEntry`] in `code`.
    pub(in crate::codegen) entries: SupportEntries,
}

/// The routines of the supporting code, called with `invoke_support`.
///
/// All routines expect `RTEMP` to contain the address of the next BPF instruction (cf.
/// `load_next_insn_addr`.) The call site passes the operands in the order listed in
/// [`Frame::operands`] (see [`save_rinsn`]), and the result, if any, is returned in `RTEMP`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub(in crate::codegen) enum SupportEntry {
    /// The entrypoint to set up the machine state VM execution expects, see `entry_point`.
    EntryPoint,
    /// `CALL_IMM` SBPFv3 onwards.
    CallImm,
    /// SBPFv0, v1 and v2 `CALL_IMM`.
    V0V1V2CallImm,
    /// Syscall trampoline.
    Syscall,
    /// `CALL_REG` of the versions that have the register of the target in the instruction (SBPFv2
    /// and v3 onwards). Takes the callee.
    Callx,
    /// SBPFv0 and v1 `CALL_REG`.
    V0V1Callx,
    /// Append registers and the pc at `RTEMP` to `vm.register_trace`.
    #[cfg(feature = "tracer")]
    Trace,
    /// Load from the address plus the offset of the instruction. Takes the address, results in
    /// the loaded value.
    LoadB,
    LoadH,
    LoadW,
    LoadDw,
    /// Store the immediate of the instruction to the address plus offset. Takes the address.
    StoreImmB,
    StoreImmH,
    StoreImmW,
    StoreImmDw,
    /// Store the value to the address plus offset. Takes the value and the address.
    StoreRegB,
    StoreRegH,
    StoreRegW,
    StoreRegDw,
    /// Takes the dividend and the divisor, results in the quotient. Terminates the execution if the
    /// divisor is zero.
    Div32,
    Div64,
    /// Likewise for the remainder.
    Mod32,
    Mod64,
    /// Likewise for the signed division, which also terminates the execution if the result
    /// overflows.
    SignedDiv32,
    SignedDiv64,
    /// Likewise for the remainder.
    SignedMod32,
    SignedMod64,
    /// Takes the dividend, results in the signed quotient of it and the immediate of the
    /// instruction. Terminates the execution if the result overflows. The immediate is not checked
    /// for zero, as the verifier rejects that.
    SignedDivImm32,
    SignedDivImm64,
    /// Likewise for the remainder.
    SignedModImm32,
    SignedModImm64,
}

impl SupportEntry {
    pub(in crate::codegen) const COUNT: usize = Self::SignedModImm64 as usize + 1;

    pub(super) const fn load(size: AccessSize) -> Self {
        [Self::LoadB, Self::LoadH, Self::LoadW, Self::LoadDw][size as usize]
    }

    pub(super) const fn store_imm(size: AccessSize) -> Self {
        [
            Self::StoreImmB,
            Self::StoreImmH,
            Self::StoreImmW,
            Self::StoreImmDw,
        ][size as usize]
    }

    pub(super) const fn store_reg(size: AccessSize) -> Self {
        [
            Self::StoreRegB,
            Self::StoreRegH,
            Self::StoreRegW,
            Self::StoreRegDw,
        ][size as usize]
    }

    pub(super) const fn divide(op: DivOp, width: Width) -> Self {
        [[Self::Div32, Self::Div64], [Self::Mod32, Self::Mod64]][op as usize][width as usize]
    }

    pub(super) const fn signed_divide(op: DivOp, width: Width) -> Self {
        [
            [Self::SignedDiv32, Self::SignedDiv64],
            [Self::SignedMod32, Self::SignedMod64],
        ][op as usize][width as usize]
    }

    pub(super) const fn signed_divide_imm(op: DivOp, width: Width) -> Self {
        [
            [Self::SignedDivImm32, Self::SignedDivImm64],
            [Self::SignedModImm32, Self::SignedModImm64],
        ][op as usize][width as usize]
    }
}

/// The offsets of the [`SupportEntry`]s from the start of the supporting code.
pub(in crate::codegen) type SupportEntries = [usize; SupportEntry::COUNT];

mod divide;
mod memory;

pub(super) use divide::{DivOp, Width};
pub(super) use memory::{AccessSize, MemoryFunctions};

pub(super) type Asm = VecAssembler<X64Relocation>;

static SUPPORTING_CODE: LazyLock<SupportingCode> = LazyLock::new(SupportingCode::generate);

impl SupportingCode {
    pub(in crate::codegen) fn get() -> &'static SupportingCode {
        &SUPPORTING_CODE
    }

    /// The offsets of the entries of a copy at `start`.
    pub(in crate::codegen) fn at(&self, start: usize) -> SupportEntries {
        self.entries.map(|entry| start.wrapping_add(entry))
    }

    fn generate() -> SupportingCode {
        let mut out = Asm::new(0);
        let mut entries = [usize::MAX; SupportEntry::COUNT];
        Self::signals(&mut out);
        entries[SupportEntry::CallImm as usize] = Self::call_imm(&mut out);
        entries[SupportEntry::V0V1V2CallImm as usize] = Self::v0v1v2_call_imm(&mut out);
        let (v0v1_callx, callx) = Self::callx(&mut out);
        entries[SupportEntry::V0V1Callx as usize] = v0v1_callx;
        entries[SupportEntry::Callx as usize] = callx;
        memory::generate(&mut out, &mut entries);
        entries[SupportEntry::Syscall as usize] = Self::syscall(&mut out);
        #[cfg(feature = "tracer")]
        {
            entries[SupportEntry::Trace as usize] = Self::trace(&mut out);
        }
        entries[SupportEntry::EntryPoint as usize] = entry::entry_point(&mut out);
        divide::generate(&mut out, &mut entries);
        assert!(
            !entries.contains(&usize::MAX),
            "an entry of the supporting code is missing"
        );
        let code = out
            .finalize()
            .expect("failed to resolve the supporting code");
        Self {
            code: code.into_boxed_slice(),
            entries,
        }
    }
}

/// The start of a support: save `RINSN`, freeing `rax`.
///
/// The supports preserve `RINSN`, so that the call site has nothing to restore. The call site
/// passes the operands in [`Frame::operands`] (see `invoke_support`), which the support must read
/// before it runs anything that may call another support, such as the BPF code of an internal call.
pub(super) fn save_rinsn(out: &mut Asm) {
    x64asm!(out; push RINSN);
}

/// The end of a support: restore `RINSN` and return. Does not touch the flags.
pub(super) fn restore_rinsn_and_return(out: &mut Asm) {
    x64asm!(out
        ; pop RINSN
        ; ret
    );
}

/// Start the code for the next support function in `out`, returning its offset.
pub(super) fn entry(out: &mut Asm) -> usize {
    x64asm!(out; .align 16);
    const { assert!(SUPPORTS_ALIGNMENT.is_multiple_of(16)) };
    out.offset().0
}

impl SupportingCode {
    /// Where the supporting functions continue when the instruction meter is exceeded.
    fn signals(out: &mut Asm) {
        x64asm!(out
            ; ->sig_meter_exceeded:
            ;; terminate(out, SIG_EXCEEDED_MAX_INSTRUCTIONS)
        );
    }
}

/// See [`super::insn::terminate`].
fn terminate(out: &mut Asm, code: i8) {
    if code != SIG_EXCEEDED_MAX_INSTRUCTIONS {
        x64asm!(out; sub RMETER, RTEMP);
    } else {
        x64asm!(out; lea RTEMP, [RMETER + 8]);
    }
    x64asm!(out
        ; mov al, code
        ; jmp QWORD [BYTE frame!(exit) + rbp]
    );
}

/// See [`super::insn::bpf_validate_meter`].
fn validate_meter(out: &mut Asm) {
    x64asm!(out
        ; cmp RTEMP, RMETER
        ; ja ->sig_meter_exceeded
    );
}

/// How the callee of [`SupportingCode::internal_call`] is given in `rax`.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Callee {
    /// Absolute address, not yet known to be within the text section.
    AbsoluteAddress,
    /// The relative offset in the text section, known to be within it.
    CheckedOffset,
}

impl SupportingCode {
    /// Call the BPF function given in `rax`, and return from the support.
    ///
    /// The meter must have been validated already.
    fn internal_call(out: &mut Asm, callee: Callee) {
        let [outside, too_deep, interpreted, resolved] = [(); 4].map(|()| out.new_dynamic_label());
        let insn_mask = (ebpf::INSN_SIZE as i8).checked_neg().unwrap();
        if callee == Callee::AbsoluteAddress {
            x64asm!(out
                ; sub rax, [BYTE frame!(text_section) + rbp]
                ; cmp rax, [BYTE frame!(text_section_len) + rbp]
                ; jae =>outside
                ; and rax, BYTE insn_mask
            );
        }
        x64asm!(out
            ; sub QWORD [BYTE frame!(calls_remaining) + rbp], 1
            // `jbe` rather than `jz`, to also catch `calls_remaining` having been 0.
            ; jbe =>too_deep

            // For converting the meter back once the callee returns.
            ; push RTEMP
            ; mov RTEMP, rax
            ; add rax, [BYTE frame!(text_section) + rbp]
            // Meter adjustments mirror the logic of the taken branch instruction.
            ; add RMETER, rax
            ; sub RMETER, [rsp]
            ; cmp QWORD [BYTE frame!(jit_pc_section) + rbp], 0
            ; je =>interpreted

            ; shr RTEMP, 1
            ; add RTEMP, [BYTE frame!(jit_pc_section) + rbp]
            ; mov WTEMP, [RTEMP]
            ; add RTEMP, [BYTE frame!(code) + rbp]
            ; add rax, BYTE ebpf::INSN_SIZE as i8
            ; mov [BYTE frame!(next_insn) + rbp], rax
            ; mov RINSN, [rsp + 8] // Saved by `save_rinsn`, above the `push` of `RTEMP`.
            ; jmp =>resolved

            ; =>interpreted
            ; movzx RTEMP, WORD [rax]
            ; shl RTEMP, InterpreterGenerator::STEP_SIZE_LOG2 as i8
            ; add RTEMP, [BYTE frame!(code) + rbp]
            ; add RINSN, BYTE ebpf::INSN_SIZE as i8

            ; =>resolved
            ; push R6
            ; push R7
            ; push R8
            ; push R9
            // `r10` is only bumped by the call itself unless the version has the programs bump it,
            // which they may do in the callee, so it is restored from where it was saved. The extra
            // push keeps the stack aligned for the call.
            ; push R10
            ; push R10
            ; add R10, [BYTE frame!(stack_frame_bump) + rbp]
            ;; debug_assert_bpf_call_stack_alignment(out)
            ; call RTEMP
            ; pop R10
            ; pop R10
            ; pop R9
            ; pop R8
            ; pop R7
            ; pop R6
            ; pop RTEMP
            // `EXIT` left the remaining budget in `RMETER`, convert back to the instruction
            // limit.
            ; add RMETER, RTEMP
            ; add QWORD [BYTE frame!(calls_remaining) + rbp], 1
            ;; restore_rinsn_and_return(out)

            ; =>outside
            ;; terminate(out, SIG_CALL_OUTSIDE_TEXT_SEGMENT)

            ; =>too_deep
            ;; terminate(out, SIG_CALL_DEPTH_EXCEEDED)
        );
    }

    fn call_imm(out: &mut Asm) -> usize {
        let start = entry(out);
        let invalid = out.new_dynamic_label();
        save_rinsn(out);
        validate_meter(out);
        x64asm!(out
            ; movsxd rax, DWORD [RTEMP - 4]
            ; lea rax, [RTEMP + rax * 8]
            ; sub rax, [BYTE frame!(text_section) + rbp]
            ; cmp rax, [BYTE frame!(text_section_len) + rbp]
            ; jae =>invalid
            ;; Self::internal_call(out, Callee::CheckedOffset)

            ; =>invalid
            ;; terminate(out, SIG_INVALID_INSN)
        );
        start
    }

    /// Returns the offsets of [`SupportEntry::V0V1Callx`] and [`SupportEntry::Callx`].
    fn callx(out: &mut Asm) -> (usize, usize) {
        let callx = entry(out);
        save_rinsn(out);
        x64asm!(out
            ; mov rax, [BYTE frame_operand(0) + rbp]
            ;; validate_meter(out)
            ; sub rax, [BYTE frame!(text_section_host_to_vm) + rbp]
            ;; Self::internal_call(out, Callee::AbsoluteAddress)
        );

        // v0 and v1 store the register in the immediate field.
        // We have to do a table dispatch based on the register number.
        const STUB_SIZE: usize = 8;
        let v0v1_callx = entry(out);
        let [invalid, stubs, common] = [(); 3].map(|()| out.new_dynamic_label());
        let last_register = (GPREG_MAP.len() as i32).checked_sub(1).unwrap();
        save_rinsn(out);
        x64asm!(out
            ; mov eax, [RTEMP - 4]
            ; cmp eax, last_register
            ; ja =>invalid
            ; push RTEMP
            ; lea RTEMP, [=>stubs]
            ; lea rax, [RTEMP + rax * 8]
            ; pop RTEMP
            ; jmp rax

            ; =>invalid
            ;; validate_meter(out)
            ;; terminate(out, SIG_INVALID_INSN)

            ; =>common
            ;; validate_meter(out)
            ; sub rax, [BYTE frame!(text_section_host_to_vm) + rbp]
            ;; Self::internal_call(out, Callee::AbsoluteAddress)

            ; .align 8
            ; =>stubs
        );
        for reg in Reg::ALL {
            let stub_start = out.offset().0;
            x64asm!(out
                ; mov rax, Rq(reg)
                ; jmp =>common
                ; .align 8
            );
            assert_eq!(out.offset().0.checked_sub(stub_start).unwrap(), STUB_SIZE);
        }
        (v0v1_callx, callx)
    }
}

impl SupportingCode {
    fn v0v1v2_call_imm(out: &mut Asm) -> usize {
        let start = entry(out);
        let [not_internal, failed] = [(); 2].map(|()| out.new_dynamic_label());
        save_rinsn(out);
        x64asm!(out
            ;; validate_meter(out)
            ;; spill_for_sysv64_call(out)
            ; mov rdi, rax
            ; mov esi, [RTEMP - 4]
            // The third argument, `remaining`.
            ;; const { assert!(RMETER == RDX) }
            ; sub RMETER, RTEMP
            ; shr RMETER, 3
            ; mov rcx, [BYTE frame!(function_registry) + rbp]
            ;; debug_assert_sysv64_call_stack_alignment(out)
            ; mov rax, [BYTE frame!(call_dispatcher) + rbp]
            ; call rax
            ; cmp dl, HostCallStatus::CallInternal as i8
            ; jne =>not_internal
            ; shl rax, 3
            ; add rax, [BYTE frame!(text_section) + rbp]
            ;; reload_after_sysv64_call(out)
            ;; Self::internal_call(out, Callee::AbsoluteAddress)

            ; =>not_internal
            ; mov RTEMP, [ BYTE SPILL_PUSHED_RTEMP + rsp ]
            ; lea RTEMP, [RTEMP + rax * 8]
            ; mov [ BYTE SPILL_PUSHED_RMETER + rsp ], RTEMP
            ; cmp dl, HostCallStatus::Ok as i8
            ;; reload_after_sysv64_call(out)
            ; jne =>failed
            ;; restore_rinsn_and_return(out)

            ; =>failed
            ;; terminate(out, SIG_PROGRAM_RESULT)
        );
        start
    }

    fn syscall(out: &mut Asm) -> usize {
        let start = entry(out);
        let failed = out.new_dynamic_label();
        save_rinsn(out);
        validate_meter(out);
        spill_for_sysv64_call(out);
        x64asm!(out
            ; mov rdi, rax
            ; mov esi, [RTEMP - 4]
            // The third argument, `remaining`.
            ;; const { assert!(RMETER == RDX) }
            ; sub RMETER, RTEMP
            ; shr RMETER, 3
            ;; debug_assert_sysv64_call_stack_alignment(out)
            ; mov rax, [BYTE frame!(call_dispatcher) + rbp]
            ; call rax
            // The syscall consumes the meter even if it failed.
            ; mov RTEMP, [ BYTE SPILL_PUSHED_RTEMP + rsp ]
            ; lea RTEMP, [RTEMP + rax * 8]
            ; mov [ BYTE SPILL_PUSHED_RMETER + rsp ], RTEMP
            ; cmp dl, HostCallStatus::Ok as i8
            ;; reload_after_sysv64_call(out)
            ; jne =>failed
            ;; restore_rinsn_and_return(out)

            ; =>failed
            ;; terminate(out, SIG_PROGRAM_RESULT)
        );
        start
    }
}

/// The address of the helper to store into [`Frame::call_dispatcher`].
pub(super) fn call_dispatcher<C: crate::vm::ContextObject>(version: SBPFVersion) -> *const u8 {
    if version.static_syscalls() {
        dispatch_syscall::<C> as *const u8
    } else {
        dispatch_call::<C> as *const u8
    }
}

/// The SBPFv0 to v2 `CALL_IMM`.
extern "sysv64" fn dispatch_call<C: crate::vm::ContextObject>(
    vm: &mut crate::vm::EbpfVm<C>,
    key: u32,
    remaining: u64,
    internal_functions: &crate::program::FunctionRegistry<usize>,
) -> HostCallResult {
    match vm.loader.get_function_registry().lookup_by_key(key) {
        Some((_, (function, _))) => invoke_syscall(vm, function, remaining),
        None => match internal_functions.lookup_by_key(key) {
            Some((_, target_pc)) => HostCallResult {
                rax: target_pc as u64,
                dl: HostCallStatus::CallInternal,
            },
            None => unsupported_syscall(vm, remaining),
        },
    }
}

extern "sysv64" fn dispatch_syscall<C: crate::vm::ContextObject>(
    vm: &mut crate::vm::EbpfVm<C>,
    key: u32,
    remaining: u64,
) -> HostCallResult {
    // TODO: avoid the hashmap lookup on every syscall. Programs only ever run against a handful of
    // syscall sets, which could get dedicated interpreter/JIT variants with the functions resolved
    // ahead of time.
    match vm.loader.get_function_registry().lookup_by_key(key) {
        Some((_, (function, _))) => invoke_syscall(vm, function, remaining),
        None => unsupported_syscall(vm, remaining),
    }
}

fn unsupported_syscall<C: crate::vm::ContextObject>(
    vm: &mut crate::vm::EbpfVm<C>,
    remaining: u64,
) -> HostCallResult {
    vm.program_result =
        crate::error::ProgramResult::Err(crate::error::EbpfError::UnsupportedInstruction);
    HostCallResult {
        rax: remaining,
        dl: HostCallStatus::Failed,
    }
}

fn invoke_syscall<C: crate::vm::ContextObject>(
    vm: &mut crate::vm::EbpfVm<C>,
    function: crate::program::BuiltinFunction<C>,
    remaining: u64,
) -> HostCallResult {
    use crate::error::ProgramResult;
    // `invoke_function` consumes `due_insn_count` from the budget and updates
    // `previous_instruction_meter` with what is left of it.
    vm.due_insn_count = vm.previous_instruction_meter.saturating_sub(remaining);
    vm.invoke_function(function);
    let status = match vm.program_result {
        ProgramResult::Ok(result) => {
            vm.registers[0] = result;
            HostCallStatus::Ok
        }
        ProgramResult::Err(_) => HostCallStatus::Failed,
    };
    HostCallResult {
        rax: vm.previous_instruction_meter,
        dl: status,
    }
}

#[cfg(feature = "tracer")]
impl SupportingCode {
    fn trace(out: &mut Asm) -> usize {
        let start = entry(out);
        save_rinsn(out);
        spill_for_sysv64_call(out);
        for reg in Reg::ALL {
            if BPF_SYSV64_CLOBBERED & 1 << u8::from(reg) == 0 {
                store_bpf_register(out, reg);
            }
        }
        let pc_slot = register_slot(Reg(GPREG_MAP.len() as u8));
        x64asm!(out
            ; sub RTEMP, [BYTE frame!(text_section) + rbp]
            ; shr RTEMP, 3
            ; dec RTEMP
            ; mov [rax + pc_slot], RTEMP
            ; mov rdi, rax
            ; mov rax, QWORD push_register_trace as *const u8 as i64
            ;; debug_assert_sysv64_call_stack_alignment(out)
            ; call rax
            ;; reload_after_sysv64_call(out)
            ;; restore_rinsn_and_return(out)
        );
        start
    }
}

#[cfg(feature = "tracer")]
extern "sysv64" fn push_register_trace(
    vm: &mut crate::vm::EbpfVm<crate::static_analysis::DummyContextObject>,
) {
    vm.register_trace.push(vm.registers);
}

const fn reg_mask(regs: &[u8]) -> u16 {
    let mut mask = 0;
    let mut i = 0;
    while i < regs.len() {
        mask |= 1 << regs[i];
        i = i.checked_add(1).unwrap();
    }
    mask
}

/// For addressing `EbpfVm` fields as `reg => Vm.field`.
type Vm = EbpfVm<'static, crate::static_analysis::DummyContextObject>;

/// General purpose registers not preserved across `sysv64` calls.
const SYSV64_CLOBBERED: u16 = reg_mask(&[RAX, RCX, RDX, RSI, RDI, R8, R9, R10, R11]);

/// The BPF registers among them.
const BPF_SYSV64_CLOBBERED: u16 = SYSV64_CLOBBERED & reg_mask(&GPREG_MAP);

/// Where `spill_for_sysv64_call` pushes `RTEMP` and `RMETER`, relative to `rsp` after it.
const SPILL_PUSHED_RTEMP: i8 = 8;
const SPILL_PUSHED_RMETER: i8 = 0;

/// Offset of the slot for `reg` in [`EbpfVm::registers`].
fn register_slot(reg: Reg) -> i32 {
    (std::mem::offset_of!(Vm, registers) as i32)
        .checked_add(i32::from(reg.0).checked_mul(8).unwrap())
        .unwrap()
}

/// Push the registers that a `sysv64` host function call would clobber.
///
/// This does not save `RINSN` as `invoke_support` will spill and restore itself.
///
/// Will leave the stack aligned for the call. Does not touch the registers or the flags.
fn push_for_sysv64_call(out: &mut Asm) {
    x64asm!(out
        ; push RTEMP
        ; push RMETER
    );
    for reg in Reg::ALL {
        if BPF_SYSV64_CLOBBERED & 1 << u8::from(reg) != 0 {
            x64asm!(out; push Rq(reg));
        }
    }
    // An even number of pushes, as the stack was aligned.
    const { assert!(BPF_SYSV64_CLOBBERED.count_ones().is_multiple_of(2)) };
}

/// Undo [`push_for_sysv64_call`]. Does not touch the flags.
fn pop_after_sysv64_call(out: &mut Asm) {
    for &reg in Reg::ALL.iter().rev() {
        if BPF_SYSV64_CLOBBERED & 1 << u8::from(reg) != 0 {
            x64asm!(out; pop Rq(reg));
        }
    }
    x64asm!(out
        ; pop RMETER
        ; pop RTEMP
    );
}

/// Like [`push_for_sysv64_call`], but spill the BPF registers into [`EbpfVm::registers`].
///
/// Leaves the `EbpfVm` in `rax`.
fn spill_for_sysv64_call(out: &mut Asm) {
    x64asm!(out
        ; push RTEMP
        ; push RMETER
        ; mov rax, [BYTE frame!(vm) + rbp]
    );
    for reg in Reg::ALL {
        if BPF_SYSV64_CLOBBERED & 1 << u8::from(reg) != 0 {
            store_bpf_register(out, reg);
        }
    }
}

/// Undo [`spill_for_sysv64_call`], taking the BPF registers from [`EbpfVm::registers`]. Does not
/// touch the flags or `rax`.
fn reload_after_sysv64_call(out: &mut Asm) {
    // `RTEMP` is popped right after.
    x64asm!(out; mov rcx, [BYTE frame!(vm) + rbp]);
    for reg in Reg::ALL {
        if BPF_SYSV64_CLOBBERED & 1 << u8::from(reg) != 0 {
            load_bpf_register(out, reg);
        }
    }
    x64asm!(out
        ; pop RMETER
        ; pop RTEMP
    );
}

/// Store the BPF register `reg` into [`EbpfVm::registers`]
///
/// Expects `EbpfVm` in `rax`.
fn store_bpf_register(out: &mut Asm, reg: Reg) {
    // Spelled out with `rax`, as a register operand makes `dynasm` encode the address with a SIB
    // byte and a 32-bit displacement.
    match i8::try_from(register_slot(reg)) {
        Ok(slot) => x64asm!(out; mov [BYTE slot + rax], Rq(reg)),
        Err(_) => {
            let slot = register_slot(reg);
            x64asm!(out; mov [DWORD slot + rax], Rq(reg))
        }
    }
}

/// Load the BPF register `reg` from [`EbpfVm::registers`]
///
/// Expects `EbpfVm` in `rcx`.
pub(super) fn load_bpf_register(out: &mut Asm, reg: Reg) {
    // See `store_bpf_register`.
    match i8::try_from(register_slot(reg)) {
        Ok(slot) => x64asm!(out; mov Rq(reg), [BYTE slot + rcx]),
        Err(_) => {
            let slot = register_slot(reg);
            x64asm!(out; mov Rq(reg), [DWORD slot + rcx])
        }
    }
}

/// Trap if the stack is not aligned for a host function call.
fn debug_assert_sysv64_call_stack_alignment(out: &mut Asm) {
    let _ = out;
}

/// Trap if the stack is not aligned for an internal call of BPF code.
fn debug_assert_bpf_call_stack_alignment(out: &mut Asm) {
    let _ = out;
}

/// Returned by the (sysv64) host functions, in the registers the fields are named after.
#[repr(C)]
struct HostCallResult {
    rax: u64,
    dl: HostCallStatus,
}

#[repr(u8)]
enum HostCallStatus {
    Ok = 0,
    /// The error has been stored into `vm.program_result`.
    Failed = 1,
    /// The SBPFv0 to v2 `CALL_IMM` is an internal call to the pc in `rax`, see `dispatch_call`.
    CallInternal = 2,
}

impl HostCallResult {
    /// Failure with the error (if any) already in place.
    fn failed() -> Self {
        Self {
            rax: 0,
            dl: HostCallStatus::Failed,
        }
    }

    /// The outcome that `vm.program_result` has been set to.
    fn of_program_result<C: crate::vm::ContextObject>(vm: &mut crate::vm::EbpfVm<C>) -> Self {
        match vm.program_result {
            crate::error::ProgramResult::Ok(rax) => Self {
                rax,
                dl: HostCallStatus::Ok,
            },
            crate::error::ProgramResult::Err(_) => Self::failed(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::codegen::generate::{interpreter, interpreter_step, jit_templates, TemplateOpcode};

    /// Whether `code`, which is at `at`, has a relative call to `address`.
    fn calls_address(code: &[u8], at: usize, address: usize) -> bool {
        code.windows(5).enumerate().any(|(position, window)| {
            let rel = i32::from_le_bytes([window[1], window[2], window[3], window[4]]);
            window[0] == 0xe8
                && at
                    .wrapping_add(position)
                    .wrapping_add(5)
                    .wrapping_add(rel as isize as usize)
                    == address
        })
    }

    fn template_opcode(op: u8, dst: u8, src: u8) -> TemplateOpcode {
        TemplateOpcode(op as u16 | (dst as u16) << 8 | (src as u16) << 12)
    }

    #[test]
    fn shared_by_all_versions() {
        let supports = SupportingCode::get();
        // `DIV64_REG` is not an instruction of the versions with `enable_pqr`, where `UDIV64_REG`
        // is the same division.
        let divide = |version: SBPFVersion| {
            let op = if version.enable_pqr() {
                ebpf::UDIV64_REG
            } else {
                ebpf::DIV64_REG
            };
            template_opcode(op, 1, 2)
        };
        let call_imm = template_opcode(ebpf::CALL_IMM, 0, 0);
        let divide_support = SupportEntry::divide(DivOp::Div, Width::W64);
        for (version, call_imm_support) in [
            (SBPFVersion::V0, SupportEntry::V0V1V2CallImm),
            (SBPFVersion::V1, SupportEntry::V0V1V2CallImm),
            (SBPFVersion::V2, SupportEntry::V0V1V2CallImm),
            (SBPFVersion::V3, SupportEntry::Syscall),
            (SBPFVersion::V4, SupportEntry::Syscall),
        ] {
            let divide = divide(version);
            let templates = jit_templates(version);
            let interpreter_supports = interpreter(version).supports() as usize;
            for (opcode, support) in [(divide, divide_support), (call_imm, call_imm_support)] {
                // The JIT output calls the latest copy of the supporting code.
                let layout = templates.insn_layout(opcode);
                assert!(templates.relocations[opcode.index()]
                    [..usize::from(layout.num_relocations)]
                    .iter()
                    .any(
                        |r| matches!(r.kind(), TemplateRelocationKind::Support(s) if s == support)
                    ));

                // SAFETY: `interpreter_step` points at the start of a step in the interpreter,
                // which is initialized, never mutated and never freed.
                let step = interpreter_step(version, opcode);
                let code = unsafe {
                    std::slice::from_raw_parts(step, 1 << InterpreterGenerator::STEP_SIZE_LOG2)
                };
                let target = interpreter_supports.wrapping_add(supports.entries[support as usize]);
                assert!(calls_address(code, step as usize, target));
            }
        }
    }
}

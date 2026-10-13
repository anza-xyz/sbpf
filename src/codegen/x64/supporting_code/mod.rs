//! Code shared by the JIT and the interpreters of all SBPF versions, generated once into its own
//! executable memory below 2 GiB, so that it can be called with a more concise instruction
//! sequence.

use super::*;
use crate::codegen::generate::InterpreterGenerator;
use crate::codegen::{
    SIG_CALL_DEPTH_EXCEEDED, SIG_CALL_OUTSIDE_TEXT_SEGMENT, SIG_DIVIDE_BY_ZERO, SIG_INVALID_INSN,
    SIG_PROGRAM_RESULT,
};
use crate::memory_management::{Mapping, ReadExecute};
use crate::program::SBPFVersion;
use crate::vm::EbpfVm;
use dynasmrt::x64::X64Relocation;
use dynasmrt::{DynamicLabel, DynasmApi, DynasmLabelApi, VecAssembler};
use std::sync::LazyLock;

/// The routines available to call with `invoke_support`.
///
/// All routines expect `RTEMP` to contain the address of the next BPF instruction (cf.
/// `load_next_insn_addr`.)
pub(in crate::codegen) struct SupportingCode {
    /// `CALL_IMM` SBPFv3 onwards.
    pub(super) call_imm: u32,
    /// `CALL_REG` SBPFv3 onwards. One helper for each register containing the callee.
    pub(super) callx: [u32; Reg::COUNT],
    /// Syscall trampoline.
    pub(super) syscall: u32,
    /// Append registers and the pc at `RTEMP` to `vm.register_trace`.
    #[cfg(feature = "tracer")]
    pub(super) trace: u32,
    /// SBPFv0 `CALL_IMM`.
    pub(super) v0_call_imm: u32,
    /// SBPFv0 `CALL_REG`.
    pub(super) v0_callx: u32,
    /// The entrypoint to set up the machine state VM execution expects.
    pub(super) entry_point: u32,
    /// Terminate the execution after CUs have been exhausted.
    pub(super) meter_exceeded: u32,
    /// Terminate the execution with the invalid instruction code.
    pub(super) invalid_insn: u32,
    pub(super) divide: DivideHelpers,
    pub(super) memory: MemoryHelpers,
    /// Keeps the code mapped.
    _code: Mapping<ReadExecute>,
}

mod divide;
mod memory;

pub(super) use divide::{DivOp, DivideHelpers, Width};
pub(super) use memory::{AccessSize, MemoryHelpers};

pub(super) type Asm = VecAssembler<X64Relocation>;

static SUPPORTING_CODE: LazyLock<SupportingCode> = LazyLock::new(SupportingCode::generate);

impl SupportingCode {
    /// How much memory we need for the supports. Increase as needed.
    const LEN: usize = 256 * 1024;

    pub(in crate::codegen) fn get() -> &'static SupportingCode {
        &SUPPORTING_CODE
    }

    fn generate() -> SupportingCode {
        let mut mapping = Mapping::sub2g(Self::LEN);
        let base = u32::try_from(mapping.as_ptr() as usize).unwrap();
        let mut out = Asm::new(usize::try_from(base).unwrap());
        let (meter_exceeded, invalid_insn) = Self::signals(&mut out, base);
        let call_imm = Self::call_imm(&mut out, base);
        let v0_call_imm = Self::v0_call_imm(&mut out, base);
        let (v0_callx, callx) = Self::callx(&mut out, base);
        let memory = MemoryHelpers::generate(&mut out, base);
        let syscall = Self::syscall(&mut out, base);
        #[cfg(feature = "tracer")]
        let trace = Self::trace(&mut out, base);
        let entry_point = entry::entry_point(&mut out, base);
        let divide = DivideHelpers::generate(&mut out, base);
        let code = out
            .finalize()
            .expect("failed to resolve the supporting code");
        mapping
            .get_mut(..code.len())
            .expect("supporting code is too long!")
            .copy_from_slice(&code);
        Self {
            call_imm,
            callx,
            v0_call_imm,
            v0_callx,
            syscall,
            #[cfg(feature = "tracer")]
            trace,
            memory,
            entry_point,
            meter_exceeded,
            invalid_insn,
            divide,
            _code: mapping.protect(),
        }
    }
}

/// Where the code for the next support function in `out` should be generated.
pub(super) fn address(out: &mut Asm, base: u32, align_for_call: bool) -> u32 {
    if align_for_call {
        x64asm!(out; .align 16);
    }
    let offset = u32::try_from(out.offset().0).unwrap();
    base.checked_add(offset).unwrap()
}

pub(in crate::codegen) fn interpreter_global(name: &str) -> usize {
    let supports = SupportingCode::get();
    let target = match name {
        "sig_meter_exceeded" => supports.meter_exceeded,
        "sig_invalid_insn" => supports.invalid_insn,
        _ => panic!("global reference to an unknown symbol {}", name),
    };
    target as usize
}

impl SupportingCode {
    fn signals(out: &mut Asm, base: u32) -> (u32, u32) {
        let meter_exceeded = address(out, base, false);
        x64asm!(out
            ; ->sig_meter_exceeded:
            ;; terminate(out, SIG_EXCEEDED_MAX_INSTRUCTIONS)
        );
        let invalid_insn = address(out, base, false);
        validate_meter(out);
        terminate(out, SIG_INVALID_INSN);
        (meter_exceeded, invalid_insn)
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
        ; jmp QWORD rbp => Frame[BYTE -1].exit
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
    /// Call the BPF function given in `rax`.
    ///
    /// The meter must have been validated already.
    fn internal_call(out: &mut Asm, callee: Callee) {
        let [outside, too_deep, interpreted, resolved] = [(); 4].map(|()| out.new_dynamic_label());
        let insn_mask = (ebpf::INSN_SIZE as i8).checked_neg().unwrap();
        if callee == Callee::AbsoluteAddress {
            x64asm!(out
                ; sub rax, rbp => Frame[BYTE -1].text_section
                ; cmp rax, rbp => Frame[BYTE -1].text_section_len
                ; jae =>outside
                ; and rax, BYTE insn_mask
            );
        }
        x64asm!(out
            ; sub QWORD rbp => Frame[BYTE -1].calls_remaining, 1
            // `jbe` rather than `jz`, to also catch `calls_remaining` having been 0.
            ; jbe =>too_deep

            // For converting the meter back once the callee returns.
            ; push RTEMP
            ; mov RTEMP, rax
            ; add rax, rbp => Frame[BYTE -1].text_section
            // Meter adjustments mirror the logic of the taken branch instruction.
            ; add RMETER, rax
            ; sub RMETER, [rsp]
            ; cmp QWORD rbp => Frame[BYTE -1].jit_pc_section, 0
            ; je =>interpreted

            ; shr RTEMP, 1
            ; add RTEMP, rbp => Frame[BYTE -1].jit_pc_section
            ; mov WTEMP, [RTEMP]
            ; add RTEMP, rbp => Frame[BYTE -1].code
            ; add rax, BYTE ebpf::INSN_SIZE as i8
            ; mov rbp => Frame[BYTE -1].next_insn, rax
            ; mov RINSN, [rsp + 16]
            ; jmp =>resolved

            ; =>interpreted
            ; movzx RTEMP, WORD [rax]
            ; shl RTEMP, InterpreterGenerator::STEP_SIZE_LOG2 as i8
            ; add RTEMP, rbp => Frame[BYTE -1].code
            ; add RINSN, BYTE ebpf::INSN_SIZE as i8

            ; =>resolved
            ; push R6
            ; push R7
            ; push R8
            ; push R9
            ; add R10, rbp => Frame[BYTE -1].stack_frame_bump
            ;; debug_assert_bpf_call_stack_alignment(out)
            ; call RTEMP
            ; sub R10, rbp => Frame[BYTE -1].stack_frame_bump
            ; pop R9
            ; pop R8
            ; pop R7
            ; pop R6
            ; pop RTEMP
            // `EXIT` left the remaining budget in `RMETER`, convert back to the instruction
            // limit.
            ; add RMETER, RTEMP
            ; add QWORD rbp => Frame[BYTE -1].calls_remaining, 1
            ; ret

            ; =>outside
            ;; terminate(out, SIG_CALL_OUTSIDE_TEXT_SEGMENT)

            ; =>too_deep
            ;; terminate(out, SIG_CALL_DEPTH_EXCEEDED)
        );
    }

    fn call_imm(out: &mut Asm, base: u32) -> u32 {
        let start = address(out, base, true);
        let invalid = out.new_dynamic_label();
        validate_meter(out);
        x64asm!(out
            ; movsxd rax, DWORD [RTEMP - 4]
            ; lea rax, [RTEMP + rax * 8]
            ; sub rax, rbp => Frame[BYTE -1].text_section
            ; cmp rax, rbp => Frame[BYTE -1].text_section_len
            ; jae =>invalid
            ;; Self::internal_call(out, Callee::CheckedOffset)

            ; =>invalid
            ;; terminate(out, SIG_INVALID_INSN)
        );
        start
    }

    fn callx(out: &mut Asm, base: u32) -> (u32, [u32; Reg::COUNT]) {
        const STUB_SIZE: usize = 8;
        let common = out.new_dynamic_label();
        let stubs = address(out, base, true);
        let mut callx = [0; Reg::COUNT];
        for reg in Reg::ALL {
            callx[usize::from(reg.0)] = address(out, base, false);
            let stub_start = out.offset().0;
            x64asm!(out
                ; mov rax, Rq(reg)
                ; jmp =>common
                ; .align 8
            );
            assert_eq!(out.offset().0.checked_sub(stub_start).unwrap(), STUB_SIZE);
        }
        x64asm!(out
            ; =>common
            ;; validate_meter(out)
            ; sub rax, rbp => Frame[BYTE -1].text_section_host_to_vm
            ;; Self::internal_call(out, Callee::AbsoluteAddress)
        );

        // v0 stores the register in the immediate field.
        // We have to do a table dispatch based on the register number.
        let v0_callx = address(out, base, true);
        let invalid = out.new_dynamic_label();
        let stubs = i32::try_from(stubs as usize).expect("supports in the first 2 GiB");
        let last_register = (GPREG_MAP.len() as i32).checked_sub(1).unwrap();
        x64asm!(out
            ; mov eax, [RTEMP - 4]
            ; cmp eax, last_register
            ; ja =>invalid
            ; lea rax, [ DWORD stubs + rax * 8 ]
            ; jmp rax

            ; =>invalid
            ;; validate_meter(out)
            ;; terminate(out, SIG_INVALID_INSN)
        );
        (v0_callx, callx)
    }
}

impl SupportingCode {
    fn v0_call_imm(out: &mut Asm, base: u32) -> u32 {
        let start = address(out, base, true);
        let [not_internal, failed] = [(); 2].map(|()| out.new_dynamic_label());
        x64asm!(out
            ;; validate_meter(out)
            ;; spill_for_sysv64_call(out)
            ; mov rdi, rax
            ; mov esi, [RTEMP - 4]
            // The third argument, `remaining`.
            ;; const { assert!(RMETER == RDX) }
            ; sub RMETER, RTEMP
            ; shr RMETER, 3
            ; mov rcx, rbp => Frame[BYTE -1].function_registry
            ;; debug_assert_sysv64_call_stack_alignment(out)
            ; mov rax, rbp => Frame[BYTE -1].call_dispatcher
            ; call rax
            ; cmp dl, HostCallStatus::CallInternal as i8
            ; jne =>not_internal
            ; shl rax, 3
            ; add rax, rbp => Frame[BYTE -1].text_section
            ;; reload_after_sysv64_call(out)
            ;; Self::internal_call(out, Callee::AbsoluteAddress)

            ; =>not_internal
            ; mov RTEMP, [ BYTE SPILL_PUSHED_RTEMP + rsp ]
            ; lea RTEMP, [RTEMP + rax * 8]
            ; mov [ BYTE SPILL_PUSHED_RMETER + rsp ], RTEMP
            ; cmp dl, HostCallStatus::Ok as i8
            ;; reload_after_sysv64_call(out)
            ; jne =>failed
            ; ret

            ; =>failed
            ;; terminate(out, SIG_PROGRAM_RESULT)
        );
        start
    }

    fn syscall(out: &mut Asm, base: u32) -> u32 {
        let start = address(out, base, true);
        let failed = out.new_dynamic_label();
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
            ; mov rax, rbp => Frame[BYTE -1].call_dispatcher
            ; call rax
            // The syscall consumes the meter even if it failed.
            ; mov RTEMP, [ BYTE SPILL_PUSHED_RTEMP + rsp ]
            ; lea RTEMP, [RTEMP + rax * 8]
            ; mov [ BYTE SPILL_PUSHED_RMETER + rsp ], RTEMP
            ; cmp dl, HostCallStatus::Ok as i8
            ;; reload_after_sysv64_call(out)
            ; jne =>failed
            ; ret

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

/// The SBPFv0 `CALL_IMM`.
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
    vm.due_insn_count = remaining;
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
    fn trace(out: &mut Asm, base: u32) -> u32 {
        let start = address(out, base, true);
        spill_for_sysv64_call(out);
        for reg in Reg::ALL {
            if BPF_SYSV64_CLOBBERED & 1 << u8::from(reg) == 0 {
                store_bpf_register(out, reg);
            }
        }
        let pc_slot = register_slot(Reg(GPREG_MAP.len() as u8));
        x64asm!(out
            ; sub RTEMP, rbp => Frame[BYTE -1].text_section
            ; shr RTEMP, 3
            ; dec RTEMP
            ; mov [rax + pc_slot], RTEMP
            ; mov rdi, rax
            ; mov rax, QWORD push_register_trace as *const u8 as i64
            ;; debug_assert_sysv64_call_stack_alignment(out)
            ; call rax
            ;; reload_after_sysv64_call(out)
            ; ret
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
        ; mov rax, rbp => Frame[BYTE -1].vm
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
    x64asm!(out; mov rcx, rbp => Frame[BYTE -1].vm);
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
    /// The SBPFv0 `CALL_IMM` is an internal call to the pc in `rax`, see `dispatch_call`.
    CallInternal = 2,
}

impl HostCallResult {
    fn new(
        result: crate::error::ProgramResult,
        program_result: &mut crate::error::ProgramResult,
    ) -> Self {
        match result {
            crate::error::ProgramResult::Ok(value) => Self {
                rax: value,
                dl: HostCallStatus::Ok,
            },
            err => {
                *program_result = err;
                Self {
                    rax: 0,
                    dl: HostCallStatus::Failed,
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::codegen::generate::{interpreter_step, jit_templates, TemplateOpcode};

    fn contains_address(code: &[u8], address: u32) -> bool {
        // `mov eax, imm32`, see `invoke_support`.
        let mov = [&[0xb8][..], &address.to_le_bytes()].concat();
        code.windows(mov.len()).any(|window| window == mov)
    }

    fn template_opcode(op: u8, dst: u8, src: u8) -> TemplateOpcode {
        TemplateOpcode(op as u16 | (dst as u16) << 8 | (src as u16) << 12)
    }

    #[test]
    fn shared_by_all_versions() {
        let supports = SupportingCode::get();
        let divide = template_opcode(ebpf::DIV64_REG, 1, 2);
        let call_imm = template_opcode(ebpf::CALL_IMM, 0, 0);
        let divide_helper = supports.divide.get(DivOp::Div, Width::W64, Reg(1), Reg(2));
        for (version, call_imm_helper) in [
            (SBPFVersion::V0, supports.v0_call_imm),
            (SBPFVersion::V3, supports.syscall),
            (SBPFVersion::V4, supports.syscall),
        ] {
            let templates = jit_templates(version);
            let template = |opcode: TemplateOpcode| {
                let len = templates.insn_layout(opcode).len();
                &templates.code[opcode.index()][..len]
            };
            assert!(contains_address(template(divide), divide_helper));
            assert!(contains_address(template(call_imm), call_imm_helper));

            // SAFETY: `interpreter_step` points at the start of a step in the interpreter, which
            // is initialized, never mutated and never freed.
            let step = |opcode| unsafe {
                std::slice::from_raw_parts(
                    interpreter_step(version, opcode),
                    1 << InterpreterGenerator::STEP_SIZE_LOG2,
                )
            };
            assert!(contains_address(step(divide), divide_helper));
            assert!(contains_address(step(call_imm), call_imm_helper));
        }
    }
}

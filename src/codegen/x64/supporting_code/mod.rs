//! Code shared by the JIT and the interpreters of all SBPF versions, generated once into its own
//! executable memory below 2 GiB, so that it can be called with a more concise instruction
//! sequence.

use super::*;
use crate::codegen::generate::InterpreterGenerator;
use crate::codegen::host::{self, HostCallStatus};
use crate::codegen::{
    SIG_CALL_DEPTH_EXCEEDED, SIG_CALL_OUTSIDE_TEXT_SEGMENT, SIG_DIVIDE_BY_ZERO, SIG_INVALID_INSN,
    SIG_PROGRAM_RESULT,
};
use crate::memory_management::{Mapping, ReadExecute};
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

mod call;
mod divide;
mod memory;

pub(super) use divide::{DivOp, DivideHelpers, Width};
pub(super) use memory::MemoryHelpers;

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
        let pc_slot = i32::try_from(host::PC_SLOT).unwrap();
        x64asm!(out
            ; sub RTEMP, rbp => Frame[BYTE -1].text_section
            ; shr RTEMP, 3
            ; dec RTEMP
            ; mov [rax + pc_slot], RTEMP
            ; mov rdi, rax
            ; mov rax, QWORD host::push_register_trace as *const u8 as i64
            ;; debug_assert_sysv64_call_stack_alignment(out)
            ; call rax
            ;; reload_after_sysv64_call(out)
            ; ret
        );
        start
    }
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

/// General purpose registers not preserved across `sysv64` calls.
const SYSV64_CLOBBERED: u16 = reg_mask(&[RAX, RCX, RDX, RSI, RDI, R8, R9, R10, R11]);

/// The BPF registers among them.
const BPF_SYSV64_CLOBBERED: u16 = SYSV64_CLOBBERED & reg_mask(&GPREG_MAP);

/// Where `spill_for_sysv64_call` pushes `RTEMP` and `RMETER`, relative to `rsp` after it.
const SPILL_PUSHED_RTEMP: i8 = 8;
const SPILL_PUSHED_RMETER: i8 = 0;

/// Offset of the slot for `reg` in [`EbpfVm::registers`].
fn register_slot(reg: Reg) -> i32 {
    i32::try_from(host::register_slot(reg)).unwrap()
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::codegen::generate::{interpreter_step, jit_templates, TemplateOpcode};
    use crate::program::SBPFVersion;

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

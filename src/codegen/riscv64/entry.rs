//! Starting the execution of the guest BPF code.

use super::supporting_code::{self, Asm, SupportingCode};
use super::*;
use crate::codegen::generate::{self, TemplateOpcode};
use crate::codegen::host::{self, register_slot};
use crate::codegen::{finish_execution, initial_meter};
use crate::elf::Executable;
use crate::program::JitProgram;
use crate::vm::{ContextObject, EbpfVm};
use dynasmrt::{DynasmApi, DynasmLabelApi};
use std::num::NonZeroU64;

/// Run `executable` starting at `vm.registers[11]`, with `vm.previous_instruction_meter` as the
/// budget.
///
/// `jit` is the `pc_section` and the machine code (in executable memory) of the JIT output for the
/// `executable`, or `None` to interpret it.
///
/// This function implements the host-side logic for starting the execution of the guest.
pub(in crate::codegen) fn enter<C: ContextObject>(
    executable: &Executable<C>,
    jit: Option<&JitProgram>,
    vm: &mut EbpfVm<C>,
) {
    let version = executable.get_sbpf_version();
    let (bpf_vm_addr, bpf) = executable.get_text_bytes();
    let pc = vm.registers[11] as usize;
    let (start_addr, insn, jit_pc_section, code) = match jit {
        Some(program) => {
            let (pc_section, text_section) = (program.pc_section(), program.text_section());
            (
                (text_section.as_ptr() as usize).wrapping_add(pc_section[pc] as usize),
                bpf.as_ptr()
                    .wrapping_add(ebpf::INSN_SIZE.wrapping_add(program.random_key as usize)),
                pc_section.as_ptr(),
                text_section.as_ptr(),
            )
        }
        None => {
            // `pc` is bounds checked by the indexing below.
            let starting_insn = bpf.as_chunks::<{ ebpf::INSN_SIZE }>().0[pc];
            let opcode = TemplateOpcode::of(u64::from_le_bytes(starting_insn));
            (
                generate::interpreter_step(version, opcode) as usize,
                bpf.as_ptr()
                    .wrapping_add(pc.wrapping_add(1).wrapping_mul(ebpf::INSN_SIZE)),
                std::ptr::null(),
                generate::interpreter(version).steps.as_ptr(),
            )
        }
    };
    let supports = SupportingCode::get();
    let config = executable.get_config();
    let meter = initial_meter(bpf, vm);
    let (max_call_depth, stack_frame_size) = (config.max_call_depth, config.stack_frame_size);
    let gaps = version.stack_frame_gaps() && config.enable_stack_frame_gaps;
    let frames_per_call = (gaps as u64).wrapping_add(1);
    let mut frame = Frame {
        exit_code: 0,
        remaining: 0,
        r0: 0,
        last_pc_address: 0,
        saved_sp: 0,
        vm: std::ptr::from_mut(vm).cast(),
        next_insn: bpf
            .as_ptr()
            .wrapping_add(pc.wrapping_add(1).wrapping_mul(ebpf::INSN_SIZE)),
        text_section: bpf.as_ptr(),
        text_section_len: bpf.len() as u64,
        text_section_limit: bpf.as_ptr_range().end,
        text_section_host_to_vm: bpf_vm_addr.wrapping_sub(bpf.as_ptr() as u64),
        jit_pc_section,
        code,
        call_dispatcher: host::call_dispatcher::<C>(version),
        memory_functions: host::MemoryFunctions::<C>::get(),
        function_registry: std::ptr::from_ref(executable.get_function_registry()).cast(),
        calls_remaining: max_call_depth as u64,
        stack_frame_bump: (stack_frame_size as u64).wrapping_mul(frames_per_call),
        supports: supports.table.as_ptr(),
        #[cfg(feature = "tracer")]
        trace: host::push_register_trace as *const u8,
    };
    // SAFETY: entry_point emits an RV64 C ABI function with this signature. The static
    // SupportingCode keeps its executable mapping alive. The entry saves all callee-saved
    // registers that the guest uses, and every exit restores the original stack and returns
    // through the saved return address. The generated code only borrows the frame for this call.
    unsafe {
        let enter: unsafe extern "C" fn(*mut Frame, usize, *const u8, u64) =
            std::mem::transmute(supports.entry_point);
        enter(&raw mut frame, start_addr, insn, meter);
    }
    let last_pc = frame.last_pc_address.wrapping_sub(bpf.as_ptr() as u64)
        / const { NonZeroU64::new(ebpf::INSN_SIZE as u64).unwrap() };
    finish_execution(
        vm,
        frame.exit_code as i8,
        frame.remaining,
        frame.r0,
        last_pc,
    );
}

/// State shared by generated code and the host for one invocation.
#[repr(C, align(16))]
pub(super) struct Frame {
    exit_code: u64,
    remaining: u64,
    r0: u64,
    last_pc_address: u64,
    /// Host stack frame holding the saved return address and callee-saved registers.
    pub(super) saved_sp: usize,
    /// The [`EbpfVm`].
    pub(super) vm: *mut u8,
    /// The address of the instruction following the target of the call (or the call just executed)
    /// in anticipation of possible invalid instruction exception.
    pub(super) next_insn: *const u8,
    pub(super) text_section: *const u8,
    /// Length of `text_section` in bytes.
    pub(super) text_section_len: u64,
    /// The end of `text_section`.
    pub(super) text_section_limit: *const u8,
    /// Translates host addresses within `text_section` to VM addresses.
    pub(super) text_section_host_to_vm: u64,
    /// Table of native code offsets indexed by guest PC. Null for interpreter execution.
    pub(super) jit_pc_section: *const u32,
    /// Code being executed. For JIT the generated machine code, for interpreter the steps base.
    pub(super) code: *const u8,
    /// See [`host::call_dispatcher`].
    pub(super) call_dispatcher: *const u8,
    /// See [`host::MemoryFunctions`].
    pub(super) memory_functions: *const u8,
    /// The `FunctionRegistry<usize>` of the executable.
    pub(super) function_registry: *const u8,
    /// How many more internal calls there can be before `CallDepthExceeded`.
    pub(super) calls_remaining: u64,
    /// How much a call moves the frame pointer by.
    pub(super) stack_frame_bump: u64,
    /// The table of the addresses of the supporting functions, see [`Support`].
    pub(super) supports: *const usize,
    /// Host function that records the register snapshot when tracing is enabled.
    #[cfg(feature = "tracer")]
    pub(super) trace: *const u8,
}

/// Enter from Rust with (frame, first machine-code address, instruction base, meter) in a0..a3.
pub(super) fn entry_point(out: &mut Asm) -> usize {
    let start = supporting_code::function_start(out);
    // ra, s0 and the eleven other callee-saved registers occupy 104 bytes.
    rv_asm!(out
        ; addi sp, sp, -112
        ; sd ra, [sp]
        ; sd RFRAME, [sp, 8]
    );
    for reg in Reg::ALL {
        rv_asm!(out; sd X(u8::from(reg)), [sp, i32::from(reg.0).wrapping_mul(8).wrapping_add(16)]);
    }
    rv_asm!(out
        ; mv RFRAME, a0
        ; sd sp, [RFRAME, frame_offset!(saved_sp)]
        ; mv RTARGET, a1
        ; mv RINSN, a2
        ; mv RMETER, a3
        ; ld RFIELD, [RFRAME, frame_offset!(vm)]
    );
    for reg in Reg::ALL {
        rv_asm!(out; ld X(u8::from(reg)), [RFIELD, register_slot(reg) as i32]);
    }
    rv_asm!(out
        ; ld RCODE, [RFRAME, frame_offset!(code)]
        ; ld RSUPPORTS, [RFRAME, frame_offset!(supports)]
        ; jal ra, ->call_bpf
        // Outermost EXIT returns here. Exceptions unwind all guest calls by reloading sp.
        ; ->exit:
        ; sd a0, [RFRAME, frame_offset!(exit_code)]
        ; sd RMETER, [RFRAME, frame_offset!(remaining)]
        ; sd R0, [RFRAME, frame_offset!(r0)]
        ; sd RTEMP, [RFRAME, frame_offset!(last_pc_address)]
        ; ld sp, [RFRAME, frame_offset!(saved_sp)]
    );
    for reg in Reg::ALL {
        rv_asm!(out; ld X(u8::from(reg)), [sp, i32::from(reg.0).wrapping_mul(8).wrapping_add(16)]);
    }
    rv_asm!(out
        ; ld RFRAME, [sp, 8]
        ; ld ra, [sp]
        ; addi sp, sp, 112
        ; ret

        // EXIT retrieves its return address from this slot, independently of nested calls.
        ; ->call_bpf:
        ; addi sp, sp, -16
        ; sd ra, [sp]
        ; jr RTARGET
    );
    start
}

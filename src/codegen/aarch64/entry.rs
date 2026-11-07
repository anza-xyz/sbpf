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
        record: [0; 2],
        saved_x19: 0,
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
    };
    let exit_code: u64;
    let last_pc_address: u64;
    let remaining: u64;
    let r0: u64;
    // SAFETY:
    //
    // Contract from `asm!`: r[asm.rules.reg-not-input]: Any registers not specified as inputs will
    // contain an undefined value on entry to the assembly code.
    //
    // Contract from `asm!`: r[asm.rules.reg-not-output]: Any registers not specified as outputs
    // must have the same value upon exiting the assembly code as they had on entry, otherwise
    // behavior is undefined.
    //
    // Contract from `asm!`: r[asm.rules.unwind]: Behavior is undefined if execution unwinds out of
    // the assembly code. This also applies if the assembly code calls a function which then
    // unwinds.
    //
    // Contract from `asm!`: r[asm.rules.mem-same-as-ffi]: The set of memory locations that assembly
    // code is allowed to read and write are the same as those allowed for an FFI function. If the
    // `readonly` option is set, then only memory reads are allowed. If the `nomem` option is set
    // then no reads or writes to memory are allowed.
    //
    // Contract from `asm!`: r[asm.rules.stack-below-sp]: Unless the `nostack` option is set,
    // assembly code is allowed to use stack space below the stack pointer. On entry to the assembly
    // code the stack pointer is guaranteed to be suitably aligned (according to the target ABI) for
    // a function call. You are responsible for making sure you don't overflow the stack (e.g. use
    // stack probing to ensure you hit a guard page). You should adjust the stack pointer when
    // allocating stack memory as required by the target ABI. The stack pointer must be restored to
    // its original value before leaving the assembly code.
    //
    // Evidence: The code only relies on the values of the registers that are inputs (`x0`, `x8`,
    // `x10`, `x12` and `x16`). `entry_point` saves `x19`, `x29`, `x30` and `sp` into the `Frame`
    // and restores them from it however deep in internal calls the execution terminates, and the
    // rest of the general purpose registers the code writes to are outputs, as are all the
    // registers `clobber_abi("C")` covers. `x18` is never written to. The host functions that the
    // generated code calls are `extern "C"`, which does not unwind (a panic in them aborts). The
    // memory the code accesses is reachable from the pointers passed in, just like for an FFI
    // function. The stack is used below the stack pointer, in 16 byte aligned increments.
    unsafe {
        std::arch::asm!(
            "blr x8",
            inout("x0") &raw mut frame => exit_code,
            lateout("x1") r0,
            inout("x10") insn => _,
            lateout("x11") last_pc_address,
            inout("x12") meter => remaining,
            inout("x8") supports.entry_point => _,
            inout("x16") start_addr => _,
            lateout("x20") _,
            lateout("x21") _,
            lateout("x22") _,
            lateout("x23") _,
            lateout("x24") _,
            lateout("x25") _,
            lateout("x26") _,
            lateout("x27") _,
            lateout("x28") _,
            clobber_abi("C"),
        );
    }
    let last_pc = last_pc_address.wrapping_sub(bpf.as_ptr() as u64)
        / const { NonZeroU64::new(ebpf::INSN_SIZE as u64).unwrap() };
    finish_execution(vm, exit_code as i8, remaining, r0, last_pc);
}

/// The state of an execution.
///
/// `RFRAME` points at it while the guest code runs, and its fields can be referred to with
/// `[RFRAME, frame_offset!(field)]`.
#[repr(C, align(16))]
pub(super) struct Frame {
    /// The frame record of the guest code, as set up by [`SupportingCode::entry_point`].
    pub(super) record: [u64; 2],
    pub(super) saved_x19: u64,
    /// The stack pointer to restore when the execution terminates.
    pub(super) saved_sp: u64,
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
    /// For the JIT output: offset in `jit_text_section` of the machine code for each instruction
    /// of `text_section`. Null for the interpreter.
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
}

/// The guest-side part of starting the execution of the guest code, and its end.
///
/// The supporting function generated here is called by [`enter`]. Expects `x0` to point at the
/// [`Frame`], `RINSN` and `RMETER` to be initialized to their namesakes, and `RTARGET` to the
/// machine code (jitted or interpreter step) for the first BPF instruction to execute.
///
/// The execution ends at the global label `exit`, with the exit code in `w0`, the address of the
/// instruction following the last one executed in `RTEMP`, the remaining budget in `RMETER` and
/// r0 in `x1`.
pub(super) fn entry_point(out: &mut Asm) -> usize {
    let start = supporting_code::function_start(out);
    a64asm!(out
        ; stp x29, x30, [x0]
        ; mov RFRAME, x0
        ; str x19, [RFRAME, frame_offset!(saved_x19)]
        ; mov RFIELD, sp
        ; str RFIELD, [RFRAME, frame_offset!(saved_sp)]
        ; ldr RFIELD, [RFRAME, frame_offset!(vm)]
        ; add RFIELD, RFIELD, register_slot(Reg(0)) as u32
        ; ldp R0, R1, [RFIELD]
        ; ldp R2, R3, [RFIELD, 16]
        ; ldp R4, R5, [RFIELD, 32]
        ; ldp R6, R7, [RFIELD, 48]
        ; ldp R8, R9, [RFIELD, 64]
        ; ldr R10, [RFIELD, 80]
        ; ldr RCODE, [RFRAME, frame_offset!(code)]
        ; ldr RSUPPORTS, [RFRAME, frame_offset!(supports)]
        ;; supporting_code::call_bpf_function(out)
        // `EXIT` at the outermost level returns here, everything else jumps.
        ; ->exit:
        ; mov x1, R0
        ; ldr RFIELD, [RFRAME, frame_offset!(saved_sp)]
        ; mov sp, RFIELD
        ; ldr x19, [RFRAME, frame_offset!(saved_x19)]
        ; ldp x29, x30, [RFRAME]
        ; ret
    );
    const { assert!(GPREG_MAP[0] == 19 && GPREG_MAP[9] == 28) };
    start
}

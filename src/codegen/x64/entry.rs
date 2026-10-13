//! Starting the execution of the guest BPF code.

use super::supporting_code::{self, address, load_bpf_register, Asm, SupportingCode};
use crate::codegen::generate::{self, Reg, TemplateOpcode};
use crate::codegen::{finish_execution, initial_meter};
use crate::ebpf;
use crate::elf::Executable;
use crate::program::JitProgram;
use crate::vm::{ContextObject, EbpfVm};
use dynasmrt::{DynasmApi, DynasmLabelApi};
use std::convert::TryFrom;
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
    let entry_point = SupportingCode::get().entry_point;
    let config = executable.get_config();
    assert!(
        config.enable_instruction_meter,
        "the instruction meter cannot be disabled"
    );
    let meter = initial_meter(bpf, vm);
    let (max_call_depth, stack_frame_size) = (config.max_call_depth, config.stack_frame_size);
    let gaps = version.stack_frame_gaps() && config.enable_stack_frame_gaps;
    let frames_per_call = (gaps as u64).wrapping_add(1);
    let mut frame = Frame {
        vm: std::ptr::from_mut(vm).cast(),
        exit: std::ptr::null(),
        next_insn: bpf
            .as_ptr()
            .wrapping_add(pc.wrapping_add(1).wrapping_mul(ebpf::INSN_SIZE)),
        text_section: bpf.as_ptr(),
        text_section_len: bpf.len() as u64,
        text_section_limit: bpf.as_ptr_range().end,
        text_section_host_to_vm: bpf_vm_addr.wrapping_sub(bpf.as_ptr() as u64),
        jit_pc_section,
        code,
        call_dispatcher: supporting_code::call_dispatcher::<C>(version),
        function_registry: std::ptr::from_ref(executable.get_function_registry()).cast(),
        calls_remaining: max_call_depth as u64,
        stack_frame_bump: (stack_frame_size as u64).wrapping_mul(frames_per_call),
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
    // Contract from `asm!`: r[asm.rules.x86-df]: On x86, the direction flag (DF in `EFLAGS`) is
    // clear on entry to the assembly code and must be clear on exit.
    //
    // Contract from `asm!`: r[asm.rules.x86-x87]: On x86, the x87 floating-point register stack
    // must remain unchanged unless all of the `st([0-7])` registers have been marked as clobbered
    // with `out("st(0)") _, out("st(1)") _, ...`.
    //
    // Contract from `asm!`: r[asm.rules.x86-prefix-restriction]: On x86, inline assembly must not
    // end with an instruction prefix (such as `LOCK`) that would apply to instructions generated by
    // the compiler.
    //
    // Evidence: The code only relies on the values of the registers that are inputs (`rsi`, `r8`,
    // `rax`, `rcx` and `rdx`). Of the general purpose registers, `rbx` is pushed and popped,
    // `entry_point` restores `rbp` and `rsp` (with `leave`, whichever depth of internal calls
    // `exit` or `terminate` jumps back from), and the rest are outputs, as are all the registers
    // `clobber_abi("sysv64")` covers, so nothing else is changed on exit. The host functions that
    // the generated code calls are `extern "sysv64"`, which does not unwind (a panic in them
    // aborts). The memory the code accesses is reachable from the pointers passed in, just like for
    // an FFI function. The stack is used below the stack pointer with pushes and calls. Nothing the
    // code emits sets the direction flag or uses x87.
    unsafe {
        std::arch::asm!(
            "push rbx",
            "call r8",
            "pop rbx",
            inout("rsi") &raw mut frame => r0,
            inout("r8") entry_point => _,
            inout("rax") insn => exit_code,
            inout("rcx") start_addr => last_pc_address,
            inout("rdx") meter => remaining,
            lateout("rdi") _,
            lateout("r9") _,
            lateout("r10") _,
            lateout("r11") _,
            lateout("r12") _,
            lateout("r13") _,
            lateout("r14") _,
            lateout("r15") _,
            lateout("xmm0") _,
            lateout("xmm1") _,
            clobber_abi("sysv64")
        );
    }
    let last_pc = last_pc_address.wrapping_sub(bpf.as_ptr() as u64)
        / const { NonZeroU64::new(ebpf::INSN_SIZE as u64).unwrap() };
    finish_execution(vm, exit_code as i8, remaining, r0, last_pc);
}

/// The state of an execution.
///
/// [`SupportingCode::entry_point`] copies it right below its frame pointer.
///
/// These fields can be referred at any time in guest code with `rbp => Frame[BYTE -1].field`.
#[repr(C, align(16))]
pub(super) struct Frame {
    /// The [`EbpfVm`].
    pub(super) vm: *mut u8,
    /// Where `terminate` jumps to. Set up by [`SupportingCode::entry_point`].
    pub(super) exit: *const u8,
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
    /// See [`supporting_code::call_dispatcher`].
    pub(super) call_dispatcher: *const u8,
    /// The `FunctionRegistry<usize>` of the executable.
    pub(super) function_registry: *const u8,
    /// How many more internal calls there can be before `CallDepthExceeded`.
    pub(super) calls_remaining: u64,
    /// How much a call moves the frame pointer by.
    pub(super) stack_frame_bump: u64,
}

/// The guest-side part of starting the execution of the guest code.
///
/// The supporting function generated here (see [`SupportingCode`]) is called by [`enter`].
pub(super) fn entry_point(out: &mut Asm, base: u32) -> u32 {
    // Expects `rsi` to point at the `Frame`, `RINSN` and `RMETER` to be initialized to their
    // namesakes, and `rcx` to the machine code (jitted or interpreter step) for the first BPF
    // instruction to execute.
    let start = address(out, base, true);
    let after_dispatch = out.new_dynamic_label();
    let frame_size = std::mem::size_of::<Frame>();
    x64asm!(out
        ; push rbp
        ; mov rbp, rsp
        ; sub rsp, BYTE i8::try_from(frame_size).unwrap()
        ; push rcx
        ; lea rdi, rbp => Frame[BYTE -1]
        ; mov ecx, (frame_size / 8) as i32
        ; rep movsq // SYSV ABI: The direction flag is clear on function entry.
        // `exit` jumps to `after_dispatch` from whatever depth of internal calls it's at.
        ; lea rdi, [ => after_dispatch ]
        ; mov rbp => Frame[BYTE -1].exit, rdi
        ; mov rcx, rbp => Frame[BYTE -1].vm
        ;; for reg in Reg::ALL { load_bpf_register(out, reg) }
        // Faster to pop+call than call a stack slot.
        ; pop rcx
        ; call rcx
        // `terminate` and exit leave the exit code in `al`, the address of the instruction
        // following the last one executed in `RTEMP`, and r0 is in `rsi`.
        ;=>after_dispatch
        ; leave
        ; ret
    );

    start
}

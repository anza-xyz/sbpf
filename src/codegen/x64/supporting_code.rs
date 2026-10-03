//! Code shared by the JIT and the interpreter, generated once into the interpreter's buffer, and
//! the host functions it calls into.

use super::*;

pub(super) struct SupportingCode {
    /// Internal call trampoline, invoked (see `invoke_support`) with the host address of the
    /// target instruction in `temp`, and the address of the instruction to return to pushed
    /// beforehand.
    pub(super) call_internal: *const u8,
    /// Syscall trampoline, invoked with the address of the instruction following the `CALL_IMM`
    /// in `temp`.
    pub(super) syscall: *const u8,
    /// Memory access helpers, by `MemoryAccessKind` and log2 of the access size. See
    /// `SupportingCode::generate_memory_access_support`.
    pub(super) memory_access: [[*const u8; 4]; 3],
    pub(super) entry_point: *const u8,
    /// See `SupportingCode::divide`.
    pub(super) divide: Vec<*const u8>,
}

unsafe impl Send for SupportingCode {}
unsafe impl Sync for SupportingCode {}

impl SupportingCode {
    /// Buffer space needed to generate this supporting code.
    pub(super) const LEN: usize = 64 * 1024;

    /// `dst` and `src` are physical registers. `None` if either isn't a BPF register.
    fn divide_index(is_div: bool, is_64: bool, is_reg: bool, dst: u8, src: u8) -> Option<usize> {
        let bpf_reg = |reg| GPREG_MAP.iter().position(|&r| r == reg);
        let kind = is_div as usize | (is_64 as usize) << 1 | (is_reg as usize) << 2;
        let src = if is_reg { bpf_reg(src)? } else { 0 };
        Some((kind * GPREG_MAP.len() + bpf_reg(dst)?) * GPREG_MAP.len() + src)
    }

    /// Helper performing the division in place on the physical registers `dst` and `src` (or the
    /// immediate.) Expects the address of the instruction following the division in `temp`.
    pub(super) fn divide(
        &self,
        is_div: bool,
        is_64: bool,
        is_reg: bool,
        dst: u8,
        src: u8,
    ) -> Option<*const u8> {
        let helper = self.divide[Self::divide_index(is_div, is_64, is_reg, dst, src)?];
        assert!(!helper.is_null());
        Some(helper)
    }

    pub(super) fn generate_into(out: &mut InterpreterGenerator) -> SupportingCode {
        Self {
            call_internal: Self::generate_call_internal_support(out),
            syscall: Self::generate_syscall_support(out),
            memory_access: Self::generate_memory_access_supports(out),
            entry_point: Self::generate_entry_point(out),
            divide: Self::generate_divide_supports(out),
        }
    }

    fn generate_call_internal_support(out: &mut InterpreterGenerator) -> *const u8 {
        // `[rsp + 24]` is the address of the instruction following the call, once the target is
        // pushed.
        let start = unsafe { out.buffer.add(out.offset()) };
        let within_depth = out.new_dynamic_label();
        let in_bounds = out.new_dynamic_label();
        x64asm!(out
            ; push RTEMP
            ; mov RTEMP, [rsp + 24]
            ;; bpf_validate_meter(out)
            ; add QWORD rbp => Frame[BYTE -1].call_depth, 1
            ; cmp QWORD rbp => Frame[BYTE -1].call_depth, MAX_CALL_DEPTH
            ; jb =>within_depth
            ;; terminate(out, SIG_CALL_DEPTH_EXCEEDED)
            ; =>within_depth
            ; mov RTEMP, [rsp]
            ; sub RTEMP, rbp => Frame[BYTE -1].text_section
            ; cmp RTEMP, rbp => Frame[BYTE -1].text_section_len
            ; jb =>in_bounds
            ; mov RTEMP, [rsp + 24]
            ;; terminate(out, SIG_CALL_OUTSIDE_TEXT_SEGMENT)
            ; =>in_bounds
            ; and RTEMP, -(ebpf::INSN_SIZE as i32)
        );

        // In the JIT, the machine code to call is found via `jit_pc_section`. Otherwise this is the
        // interpreter, and `insn` needs to point past the target instead.
        let base_addr = i32::try_from(out.buffer as usize).expect("interpreter in first 2GB");
        let translated = out.new_dynamic_label();
        let resolved = out.new_dynamic_label();
        x64asm!(out
            // `insn` is restored after the call: the JIT's never changes, and the interpreter's
            // is the instruction following the call.
            ; push RINSN
            ; add RTEMP, rbp => Frame[BYTE -1].text_section
            ; mov [rsp + 8], RTEMP
            ; cmp QWORD rbp => Frame[BYTE -1].jit_pc_section, 0
            ; je =>translated
            // JIT specific: translate the jump address to a machine code address
            ; sub RTEMP, rbp => Frame[BYTE -1].text_section
            ; shr RTEMP, 1
            ; add RTEMP, rbp => Frame[BYTE -1].jit_pc_section
            ; mov WTEMP, [RTEMP]
            ; add RTEMP, rbp => Frame[BYTE -1].jit_text_section
            ; jmp =>resolved
            ; =>translated
            ; lea RINSN, [RTEMP + 8]
            ; movzx RTEMP, WORD [RTEMP]
            ; shl RTEMP, InterpreterGenerator::STEP_SIZE_LOG2 as i8
            ; lea RTEMP, [ DWORD base_addr + RTEMP ]
        );
        // `temp` is the code to call, `[rsp + 8]` the target instruction.
        x64asm!(out
            ; =>resolved
            // Like a taken branch, from the instruction following the call to the target.
            ; add RMETER, [rsp + 8]
            ; sub RMETER, [rsp + 32]
            ; push RTEMP
            // The callee gets the address of the instruction following it in `temp`, as
            // `load_next_insn` would produce it.
            ; mov RTEMP, [rsp + 16]
            ; add RTEMP, ebpf::INSN_SIZE as i32
            ; push R6
            ; push R7
            ; push R8
            ; push R9
            ; push R10
            ; add R10, STACK_FRAME_SIZE
            ; call QWORD [rsp + 40]
            ; pop R10
            ; pop R9
            ; pop R8
            ; pop R7
            ; pop R6
            // FIXME: adjust the stack layout such that this code be a single `add rsp...`
            ; add rsp, 8
            ; pop RINSN
            ; add rsp, 8
            // `EXIT` leaves the remaining budget in `meter`, convert back to the instruction limit.
            ; add RMETER, [rsp + 16]
            ; sub QWORD rbp => Frame[BYTE -1].call_depth, 1
            ; ret
        );

        start
    }

    /// The helpers by `MemoryAccessKind` and log2 of the access size.
    fn generate_memory_access_supports(out: &mut InterpreterGenerator) -> [[*const u8; 4]; 3] {
        let kinds = [
            MemoryAccessKind::Load,
            MemoryAccessKind::StoreImm,
            MemoryAccessKind::StoreReg,
        ];
        kinds.map(|kind| {
            std::array::from_fn(|size_log2| {
                Self::generate_memory_access_support(out, kind, size_log2)
            })
        })
    }

    /// The helpers for `divide`.
    fn generate_divide_supports(out: &mut InterpreterGenerator) -> Vec<*const u8> {
        let last_reg = *GPREG_MAP.last().unwrap();
        let mut divide = vec![
            std::ptr::null();
            Self::divide_index(true, true, true, last_reg, last_reg).unwrap() + 1
        ];
        for is_div in [false, true] {
            for is_64 in [false, true] {
                for is_reg in [false, true] {
                    for &dst_reg in &GPREG_MAP {
                        let src_regs = if is_reg {
                            &GPREG_MAP[..]
                        } else {
                            &GPREG_MAP[..1]
                        };
                        for &src_reg in src_regs {
                            let index = Self::divide_index(is_div, is_64, is_reg, dst_reg, src_reg)
                                .unwrap();
                            divide[index] = unsafe { out.buffer.add(out.offset()) };
                            Self::generate_div_mod_support(
                                out, is_div, is_64, is_reg, dst_reg, src_reg,
                            );
                        }
                    }
                }
            }
        }

        divide
    }

    fn generate_entry_point(out: &mut InterpreterGenerator) -> *const u8 {
        // Expects `rsi` to point at the `Frame`, and `RINSN` and `RMETER` to be initialized to
        // their namesakes.
        let start = unsafe { out.buffer.add(out.offset()) };
        let after_dispatch = out.new_dynamic_label();
        let frame_size = std::mem::size_of::<Frame>();
        x64asm!(out
            ; push rbp
            ; mov rbp, rsp
            ; sub rsp, frame_size as i32
            ; lea rdi, rbp => Frame[BYTE -1]
            ; mov ecx, (frame_size / 8) as i32
            ; rep movsq // SYSV ABI: The direction flag is clear on function entry.
            // `exit` jumps to `after_dispatch` from whatever depth of internal calls it's at.
            ; lea rdi, [ => after_dispatch ]
            ; mov rbp => Frame[BYTE -1].exit, rdi
            ; mov rsi, rbp => Frame[BYTE -1].vm
        );
        // `rsi` is one of the BPF registers, but temporarily holds the `EbpfVm` right now, so it is
        // overwritten last.
        const { assert!(GPREG_MAP[0] == RSI) };
        for (i, &reg) in GPREG_MAP.iter().enumerate().rev() {
            x64asm!(out; mov Rq(reg), [rsi + RuntimeEnvironmentSlot::Registers as i32 + i as i32 * 8]);
        }

        x64asm!(out
            ; call QWORD rbp => Frame[BYTE -1].start
            ;=>after_dispatch
            ; mov rax, rbp => Frame[BYTE -1].vm
        );
        for (i, &reg) in GPREG_MAP.iter().enumerate() {
            x64asm!(out; mov [rax + RuntimeEnvironmentSlot::Registers as i32 + i as i32 * 8], Rq(reg));
        }
        x64asm!(out
            ; mov rsp, rbp
            ; pop rbp
            ; ret
        );

        start
    }

    fn generate_syscall_support(out: &mut InterpreterGenerator) -> *const u8 {
        let start = unsafe { out.buffer.add(out.offset()) };
        bpf_validate_meter(out);
        // `vm.invoke_function` takes the arguments from `vm.registers`, where
        // `clobber_for_sysv64_call` spills them.
        let pushed = clobber_for_sysv64_call(out);
        // Also the return address and `invoke_support`'s target.
        let needs_stack_alignment = sysv64_call_needs_stack_alignment(pushed + 16);
        x64asm!(out
            ; mov rdi, rax
            ; mov esi, [RTEMP - 4]
            // `rdx` is `meter`.
            ; sub rdx, RTEMP
            ; shr rdx, 3
        );
        if needs_stack_alignment {
            x64asm!(out; sub rsp, 8);
        }
        debug_assert_sysv64_call_stack_alignment(out);
        x64asm!(out; call QWORD rbp => Frame[BYTE -1].syscall_dispatcher);
        if needs_stack_alignment {
            x64asm!(out; add rsp, 8);
        }
        let failed = out.new_dynamic_label();
        x64asm!(out
            // The syscall has consumed the budget even if it failed. `clobber_for_sysv64_call`
            // has pushed `temp` and `meter` last.
            ;; const { assert!(SYSV64_PUSHED >> RTEMP == 1 | 1 << (RMETER - RTEMP)) }
            ; mov rcx, [rsp + 8]
            ; lea rcx, [rcx + rax * 8]
            ; mov [rsp], rcx
            // `HostCallResult::is_err`.
            ; test dl, dl
            ;; restore_from_sysv64_call(out)
            ; jnz =>failed
            ; ret
            ; =>failed
            ;; terminate(out, SIG_PROGRAM_RESULT)
        );
        start
    }

    /// Expects the base address and, for `MemoryAccessKind::StoreReg`, the value to store pushed
    /// (in that order.) Loads replace the base address with the loaded value.
    fn generate_memory_access_support(
        out: &mut InterpreterGenerator,
        kind: MemoryAccessKind,
        size_log2: usize,
    ) -> *const u8 {
        let start = unsafe { out.buffer.add(out.offset()) };
        let function = match (kind, size_log2) {
            (MemoryAccessKind::Load, 0) => load::<u8> as *const u8,
            (MemoryAccessKind::Load, 1) => load::<u16> as *const u8,
            (MemoryAccessKind::Load, 2) => load::<u32> as *const u8,
            (MemoryAccessKind::Load, 3) => load::<u64> as *const u8,
            (_, 0) => store::<u8> as *const u8,
            (_, 1) => store::<u16> as *const u8,
            (_, 2) => store::<u32> as *const u8,
            (_, 3) => store::<u64> as *const u8,
            _ => unreachable!(),
        };
        let pushed = clobber_for_sysv64_call(out);
        // Past the return address and `invoke_support`'s target are the values pushed by the
        // caller, the most recent first.
        let values = pushed + 16;
        let value_count = match kind {
            MemoryAccessKind::Load | MemoryAccessKind::StoreImm => 1,
            MemoryAccessKind::StoreReg => 2,
        };
        let base = i8::try_from(values + (value_count - 1) * 8).unwrap();
        match kind {
            MemoryAccessKind::Load => {}
            MemoryAccessKind::StoreImm => x64asm!(out; movsxd rdx, DWORD [RTEMP - 4]),
            MemoryAccessKind::StoreReg => {
                let value = i8::try_from(values).unwrap();
                x64asm!(out; mov rdx, [ BYTE value + rsp ])
            }
        }
        x64asm!(out
            ; movsx rsi, WORD [RTEMP - 6]
            ; add rsi, [ BYTE base + rsp ]
            ; mov rdi, [rax + RuntimeEnvironmentSlot::MemoryMapping as i32]
            ; add rax, RuntimeEnvironmentSlot::ProgramResult as i32
        );
        match kind {
            MemoryAccessKind::Load => x64asm!(out; mov rdx, rax),
            MemoryAccessKind::StoreImm | MemoryAccessKind::StoreReg => x64asm!(out; mov rcx, rax),
        }
        let needs_stack_alignment = sysv64_call_needs_stack_alignment(values + value_count * 8);
        x64asm!(out; mov rax, QWORD function as i64);
        if needs_stack_alignment {
            x64asm!(out; sub rsp, 8);
        }
        debug_assert_sysv64_call_stack_alignment(out);
        x64asm!(out; call rax);
        if needs_stack_alignment {
            x64asm!(out; add rsp, 8);
        }
        if kind == MemoryAccessKind::Load {
            x64asm!(out; mov [ BYTE base + rsp ], rax);
        }
        let failed = out.new_dynamic_label();
        x64asm!(out
            // `HostCallResult::is_err`.
            ; test dl, dl
            ;; restore_from_sysv64_call(out)
            ; jnz =>failed
            ; ret
            ; =>failed
            // Running out of budget takes precedence over the error.
            ;; bpf_validate_meter(out)
            ;; terminate(out, SIG_PROGRAM_RESULT)
        );
        start
    }

    fn generate_div_mod_support(
        out: &mut InterpreterGenerator,
        is_div: bool,
        is_64: bool,
        is_reg: bool,
        dst: u8,
        src: u8,
    ) {
        if is_reg {
            // FIXME: there might be a better way to test this...
            if is_64 {
                x64asm!(out; test Rq(src), Rq(src));
            } else {
                x64asm!(out; test Rd(src), Rd(src));
            }
            let non_zero = out.new_dynamic_label();
            x64asm!(out
                ; jnz =>non_zero
                ;; bpf_validate_meter(out)
                ;; terminate(out, SIG_DIVIDE_BY_ZERO)
                ; =>non_zero
                ; mov RTEMP, Rq(src)
            );
        } else {
            // The verifier rejects zero immediates, so there's no need to check those.
            x64asm!(out; movsxd RTEMP, DWORD [RTEMP - 4]);
        }
        x64asm!(out
            ; push rax
            ; push rdx
            ; xor edx, edx
        );
        match (is_64, is_div) {
            (true, true) => x64asm!(out
                ; mov rax, Rq(dst)
                ; div RTEMP
                ; mov Rq(dst), rax
            ),
            (true, false) => x64asm!(out
                ; mov rax, Rq(dst)
                ; div RTEMP
                ; mov Rq(dst), rdx
            ),
            (false, true) => x64asm!(out
                ; mov eax, Rd(dst)
                ; div WTEMP
                ; mov Rd(dst), eax
            ),
            (false, false) => x64asm!(out
                ; mov eax, Rd(dst)
                ; div WTEMP
                ; mov Rd(dst), edx
            ),
        }
        x64asm!(out
            ; pop rdx
            ; pop rax
            ; ret
        );
    }
}

const fn reg_mask(regs: &[u8]) -> u16 {
    let mut mask = 0;
    let mut i = 0;
    while i < regs.len() {
        mask |= 1 << regs[i];
        i += 1;
    }
    mask
}

/// General purpose registers not preserved across `sysv64` calls.
const SYSV64_CLOBBERED: u16 = reg_mask(&[RAX, RCX, RDX, RSI, RDI, R8, R9, R10, R11]);
/// The registers `clobber_for_sysv64_call` pushes, rather than spills into `vm.registers`.
const SYSV64_PUSHED: u16 = SYSV64_CLOBBERED & !reg_mask(&GPREG_MAP);

/// Save the registers that a `sysv64` host function call would clobber: the rest are pushed in
/// the order of their register numbers (for the internal registers that is `insn`, `temp`,
/// `meter`), the BPF registers are spilled into `vm.registers`. Leaves the `EbpfVm` in `rax`.
///
/// Returns the number of bytes pushed. The stack is not aligned for the call, see
/// `sysv64_call_needs_stack_alignment`. Does not touch the flags.
fn clobber_for_sysv64_call(out: &mut InterpreterGenerator) -> i32 {
    for reg in 0..16 {
        if SYSV64_PUSHED & 1 << reg != 0 {
            x64asm!(out; push Rq(reg));
        }
    }
    const { assert!(SYSV64_PUSHED & 1 << RAX != 0) };
    x64asm!(out; mov rax, rbp => Frame[BYTE -1].vm);
    for (i, &reg) in GPREG_MAP.iter().enumerate() {
        if SYSV64_CLOBBERED & 1 << reg != 0 {
            x64asm!(out; mov [rax + RuntimeEnvironmentSlot::Registers as i32 + i as i32 * 8], Rq(reg));
        }
    }
    SYSV64_PUSHED.count_ones() as i32 * 8
}

/// Does `rsp` need to be adjusted by 8 bytes for a host function call, given the number of bytes
/// pushed since the BPF code? The stack is always aligned in the BPF code.
const fn sysv64_call_needs_stack_alignment(pushed: i32) -> bool {
    pushed % 16 != 0
}

/// Trap if the stack is not aligned for a host function call.
fn debug_assert_sysv64_call_stack_alignment(out: &mut InterpreterGenerator) {
    #[cfg(feature = "codegen_debug")]
    {
        let aligned = out.new_dynamic_label();
        x64asm!(out
            ; test esp, 15
            ; jz =>aligned
            ; int3
            ; =>aligned
        );
    }
    #[cfg(not(feature = "codegen_debug"))]
    let _ = out;
}

/// Restore the registers saved by `clobber_for_sysv64_call`. Does not touch the flags.
fn restore_from_sysv64_call(out: &mut InterpreterGenerator) {
    x64asm!(out; mov rax, rbp => Frame[BYTE -1].vm);
    for (i, &reg) in GPREG_MAP.iter().enumerate() {
        if SYSV64_CLOBBERED & 1 << reg != 0 {
            x64asm!(out; mov Rq(reg), [rax + RuntimeEnvironmentSlot::Registers as i32 + i as i32 * 8]);
        }
    }
    for reg in (0..16).rev() {
        if SYSV64_PUSHED & 1 << reg != 0 {
            x64asm!(out; pop Rq(reg));
        }
    }
}

/// Returned by the host functions in `rax:dl`.
#[repr(C)]
struct HostCallResult {
    value: u64,
    /// The error has been stored into `vm.program_result`.
    is_err: bool,
}

impl HostCallResult {
    fn new(
        result: crate::error::ProgramResult,
        program_result: &mut crate::error::ProgramResult,
    ) -> Self {
        match result {
            crate::error::ProgramResult::Ok(value) => Self {
                value,
                is_err: false,
            },
            err => {
                *program_result = err;
                Self {
                    value: 0,
                    is_err: true,
                }
            }
        }
    }
}

extern "sysv64" fn load<T: crate::aligned_memory::Pod + Into<u64>>(
    mapping: &mut crate::memory_region::MemoryMapping,
    vm_addr: u64,
    result: &mut crate::error::ProgramResult,
) -> HostCallResult {
    HostCallResult::new(mapping.load::<T>(vm_addr), result)
}

extern "sysv64" fn store<T: crate::aligned_memory::Pod>(
    mapping: &mut crate::memory_region::MemoryMapping,
    vm_addr: u64,
    value: u64,
    result: &mut crate::error::ProgramResult,
) -> HostCallResult {
    const { assert!(cfg!(target_endian = "little")) };
    // Truncates `value`.
    let value = unsafe { std::mem::transmute_copy::<u64, T>(&value) };
    HostCallResult::new(mapping.store::<T>(value, vm_addr), result)
}

/// `remaining` is the budget left after the `CALL_IMM` instruction itself.
/// The address of the function to store into `Frame::syscall_dispatcher`.
pub(super) fn syscall_dispatcher<C: crate::vm::ContextObject>() -> *const u8 {
    dispatch_syscall::<C> as *const u8
}

extern "sysv64" fn dispatch_syscall<C: crate::vm::ContextObject>(
    vm: &mut crate::vm::EbpfVm<C>,
    key: u32,
    remaining: u64,
) -> HostCallResult {
    use crate::error::ProgramResult;
    // TODO: avoid the lookup on every syscall. Programs only ever run against a handful of
    // syscall sets, which could get dedicated interpreter/JIT variants with the functions resolved
    // ahead of time.
    let Some((_, (function, _))) = vm.loader.get_function_registry().lookup_by_key(key) else {
        vm.program_result = ProgramResult::Err(crate::error::EbpfError::UnsupportedInstruction);
        return HostCallResult {
            value: remaining,
            is_err: true,
        };
    };
    vm.due_insn_count = remaining;
    vm.invoke_function(function);
    let is_err = match vm.program_result {
        ProgramResult::Ok(result) => {
            vm.registers[0] = result;
            false
        }
        ProgramResult::Err(_) => true,
    };
    HostCallResult {
        value: vm.previous_instruction_meter,
        is_err,
    }
}

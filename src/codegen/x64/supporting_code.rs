//! Code shared by the JIT and the interpreters of all SBPF versions, generated once into its own
//! executable memory, and the host functions it calls into.

use super::*;
use dynasmrt::x64::X64Relocation;
use dynasmrt::{DynasmApi, DynasmLabelApi, VecAssembler};

pub(in crate::codegen) struct SupportingCode {
    /// Internal call trampoline, invoked (see `invoke_support`) with the host address of the
    /// target instruction in `RTEMP`, and the address of the BPF instruction to return to pushed
    /// beforehand.
    pub(super) call_internal: *const u8,
    /// `CALL_IMM` SBPFv3 onwards.
    pub(super) call_imm: *const u8,
    /// Syscall trampoline.
    pub(super) syscall: *const u8,
    /// Appends the registers and the pc of the instruction preceding the address in `TEMP` to
    /// `vm.register_trace`.
    #[cfg(feature = "tracer")]
    pub(super) trace: *const u8,
    /// SBPFv0 `CALL_IMM`, which is a syscall or an internal call depending on the immediate.
    pub(super) v0_call_imm: *const u8,
    /// SBPFv0 `CALL_REG`, which computes the register from the immediate.
    pub(super) v0_callx: *const u8,
    pub(super) entry_point: *const u8,
    /// See `SupportingCode::divide`.
    pub(super) divide: [[[*const u8; Reg::COUNT]; Reg::COUNT]; 4],
    /// Loads, by log2 of the access size, destination and source register.
    pub(super) load: [[[*const u8; Reg::COUNT]; Reg::COUNT]; 4],
    /// Stores of the immediate, by log2 of the access size and destination register.
    pub(super) store_imm: [[*const u8; Reg::COUNT]; 4],
    /// Stores of a register, by log2 of the access size, destination and source register.
    pub(super) store_reg: [[[*const u8; Reg::COUNT]; Reg::COUNT]; 4],
    /// The jump stubs `v0_callx` dispatches to, which precede it.
    #[cfg(feature = "codegen_debug")]
    callx_stubs: *const u8,
    /// The addresses of all the generated code.
    #[cfg(feature = "codegen_debug")]
    code_range: std::ops::Range<usize>,
}

// SAFETY: the pointers are only used for their addresses, as the memory they point into is
// read-execute and is never freed or written to once the `SupportingCode` is constructed.
unsafe impl Send for SupportingCode {}
// SAFETY: see `Send`.
unsafe impl Sync for SupportingCode {}

type Asm = VecAssembler<X64Relocation>;

/// The supporting code of all SBPF versions, which the JIT output and the interpreters of all of
/// them share.
static SUPPORTING_CODE: LazyLock<SupportingCode> = LazyLock::new(SupportingCode::generate);

impl SupportingCode {
    /// Size of the executable memory the supporting code is generated into.
    const LEN: usize = 256 * 1024;

    pub(in crate::codegen) fn get() -> &'static SupportingCode {
        &SUPPORTING_CODE
    }

    /// The generated code, and the address of each of its routines.
    #[cfg(feature = "codegen_debug")]
    pub(in crate::codegen) fn debug_symbols(
        &self,
    ) -> (std::ops::Range<usize>, Vec<(String, usize)>) {
        let mut symbols = vec![
            ("call_internal".to_string(), self.call_internal as usize),
            ("call_imm".to_string(), self.call_imm as usize),
            ("v0_call_imm".to_string(), self.v0_call_imm as usize),
            ("v0_callx_stubs".to_string(), self.callx_stubs as usize),
            ("v0_callx".to_string(), self.v0_callx as usize),
            ("syscall".to_string(), self.syscall as usize),
            ("entry_point".to_string(), self.entry_point as usize),
        ];
        #[cfg(feature = "tracer")]
        symbols.push(("trace".to_string(), self.trace as usize));
        for size_log2 in 0..4 {
            let bits = 8usize << size_log2;
            for dst in 0..Reg::COUNT {
                let store_imm = self.store_imm[size_log2][dst] as usize;
                symbols.push((format!("store_imm_u{bits}_r{dst}"), store_imm));
                for src in 0..Reg::COUNT {
                    let load = self.load[size_log2][dst][src] as usize;
                    symbols.push((format!("load_u{bits}_r{dst}_r{src}"), load));
                    let store_reg = self.store_reg[size_log2][dst][src] as usize;
                    symbols.push((format!("store_reg_u{bits}_r{dst}_r{src}"), store_reg));
                }
            }
        }
        // Indexed like `SupportingCode::divide`.
        let operations = ["mod32", "div32", "mod64", "div64"];
        for (operation, helpers) in operations.iter().zip(&self.divide) {
            for (dst, row) in helpers.iter().enumerate() {
                for (src, helper) in row.iter().enumerate() {
                    symbols.push((
                        format!("divide_{operation}_r{dst}_r{src}"),
                        *helper as usize,
                    ));
                }
            }
        }
        (self.code_range.clone(), symbols)
    }

    /// Helper performing the division in place on the registers `dst` and `src`. Expects the
    /// address of the instruction following the division in `temp`.
    pub(super) fn divide(&self, is_div: bool, is_64: bool, dst: Reg, src: Reg) -> *const u8 {
        self.divide[is_div as usize | (is_64 as usize) << 1][dst.0 as usize][src.0 as usize]
    }

    fn generate() -> SupportingCode {
        // Addressed with absolute 32-bit addresses, so it has to be within the first 2 GiB.
        let buffer = allocate_pages_low(Self::LEN)
            .expect("failed to allocate memory for the supporting code");
        #[cfg(all(feature = "codegen_debug", target_os = "linux"))]
        // SAFETY:
        //
        // Contract from `CodeFile::map`: the range must be page aligned, owned by the caller, not
        // accessed meanwhile, and without content that is needed.
        // Evidence: it is the fresh allocation of `allocate_pages_low`, which is page aligned, and
        // `LEN` is a multiple of the page size. Nothing was written to it, and nothing else refers
        // to it. The mapping stays, as the supporting code is never freed.
        let code_file =
            unsafe { super::super::debug::CodeFile::map("supports", buffer as usize, Self::LEN) };
        let (supports, code) = Self::assemble(buffer as usize);
        assert!(code.len() <= Self::LEN, "supporting code is too long!");
        // SAFETY:
        //
        // Contract from `ptr::copy_nonoverlapping`: the source and the destination must be valid
        // for `code.len()` bytes, and not overlap.
        // Evidence: `code.len()` was asserted to fit the `LEN` bytes of the fresh read-write
        // allocation, which `code`, a `Vec`, cannot overlap.
        unsafe { std::ptr::copy_nonoverlapping(code.as_ptr(), buffer, code.len()) };
        #[cfg(all(feature = "codegen_debug", target_os = "linux"))]
        super::super::debug::finish_supporting_code(code_file, &supports);
        // SAFETY:
        //
        // Contract from `protect_pages`: the range must be whole pages of a mapping that the
        // caller owns, and nothing may access them in a way the new permissions disallow.
        // Evidence: it is the whole allocation of `allocate_pages_low`, which is page aligned, and
        // `LEN` is a multiple of the page size. The code is only executed afterwards.
        unsafe { protect_pages(buffer, Self::LEN, PagePermissions::ReadExecute) }
            .expect("failed to make the supporting code executable");
        supports
    }

    /// Assemble the supporting code to run from the address `base`.
    fn assemble(base: usize) -> (SupportingCode, Vec<u8>) {
        let mut out = Asm::new(base);
        let call_internal_label = out.new_dynamic_label();
        let target_checked = out.new_dynamic_label();
        let call_internal =
            Self::call_internal(&mut out, base, call_internal_label, target_checked);
        let call_imm = Self::call_imm(&mut out, base, target_checked);
        let v0_call_imm = Self::v0_call_imm(&mut out, base, call_internal_label);
        #[cfg_attr(not(feature = "codegen_debug"), allow(unused_variables))]
        let (v0_callx, callx_stubs) = Self::callx_target(&mut out, base, call_internal_label);
        let (load, store_imm, store_reg) = Self::memory_accesses(&mut out, base);
        let supports = Self {
            call_internal,
            call_imm,
            v0_call_imm,
            v0_callx,
            syscall: Self::syscall(&mut out, base),
            #[cfg(feature = "tracer")]
            trace: Self::trace(&mut out, base),
            load,
            store_imm,
            store_reg,
            entry_point: Self::entry_point(&mut out, base),
            divide: Self::divides(&mut out, base),
            #[cfg(feature = "codegen_debug")]
            callx_stubs,
            #[cfg(feature = "codegen_debug")]
            code_range: base..base.wrapping_add(out.offset().0),
        };
        let code = out
            .finalize()
            .expect("failed to resolve the supporting code");
        (supports, code)
    }

    /// `target_checked` is where `call_imm` continues, once the target is checked to be within
    /// the text section and is in `TEMP` as an offset into it.
    fn call_internal(
        out: &mut Asm,
        base: usize,
        label: DynamicLabel,
        target_checked: DynamicLabel,
    ) -> *const u8 {
        let start = address(out, base, true);
        x64asm!(out; =>label);
        let within_depth = out.new_dynamic_label();
        let in_bounds = out.new_dynamic_label();
        let insn_mask = (ebpf::INSN_SIZE as i32).checked_neg().unwrap();
        x64asm!(out
            ; push RINSN
            ; push RTEMP
            // `[rsp + 32]` is the address of the BPF instruction following the call.
            ; mov RTEMP, [rsp + 32]
            ;; validate_meter(out)
            ; mov RTEMP, [rsp]
            ; sub RTEMP, rbp => Frame[BYTE -1].text_section
            ; cmp RTEMP, rbp => Frame[BYTE -1].text_section_len
            ; jb =>in_bounds
            ; mov RTEMP, [rsp + 32]
            ;; terminate(out, SIG_CALL_OUTSIDE_TEXT_SEGMENT)
            ; =>in_bounds
            ; and RTEMP, insn_mask
            ; =>target_checked
            ; sub QWORD rbp => Frame[BYTE -1].calls_remaining, 1
            // This cc code is load-bearing for when `calls_remaining == 0`.
            ; ja =>within_depth
            ; mov RTEMP, [rsp + 32]
            ;; terminate(out, SIG_CALL_DEPTH_EXCEEDED)
            ; =>within_depth
        );

        // In the JIT, the machine code to call is found via `jit_pc_section`. Otherwise this is the
        // interpreter, and `RINSN` needs to point past the target instead.
        let translated = out.new_dynamic_label();
        let resolved = out.new_dynamic_label();
        x64asm!(out
            ; add RTEMP, rbp => Frame[BYTE -1].text_section
            ; mov [rsp], RTEMP
            ; cmp QWORD rbp => Frame[BYTE -1].jit_pc_section, 0
            ; je =>translated
            // JIT specific: translate the jump address to a machine code address
            ; sub RTEMP, rbp => Frame[BYTE -1].text_section
            ; shr RTEMP, 1
            ; add RTEMP, rbp => Frame[BYTE -1].jit_pc_section
            ; mov WTEMP, [RTEMP]
            ; jmp =>resolved
            ; =>translated
            ; lea RINSN, [RTEMP + 8]
            ; movzx RTEMP, WORD [RTEMP]
            ; shl RTEMP, InterpreterGenerator::STEP_SIZE_LOG2 as i8
        );
        // `RTEMP` is the offset within `code` to call, `[rsp]` the target instruction.
        x64asm!(out
            ; =>resolved
            ; add RTEMP, rbp => Frame[BYTE -1].code
            // Meter adjustments mirror the logic of the taken branch instruction.
            ; add RMETER, [rsp]
            ; sub RMETER, [rsp + 32]
            ; push RTEMP
            // The callee gets the address of the instruction following it in `RTEMP`, as
            // `load_next_insn` would produce it.
            ; mov RTEMP, [rsp + 8]
            ; add RTEMP, ebpf::INSN_SIZE as i32
            ; push R6
            ; push R7
            ; push R8
            ; push R9
            // `r10` is read-only in the SBPF versions this runs, so this push is not for
            // preserving it, but keeps the stack aligned for the host calls of the callee (see
            // `sysv64_call_needs_stack_alignment`). Popping it is also cheaper than undoing the
            // bump.
            ; push R10
            ; add R10, rbp => Frame[BYTE -1].stack_frame_bump
            ;; debug_assert_bpf_call_stack_alignment(out)
            ; call QWORD [rsp + 40]
            ; pop R10
            ; pop R9
            ; pop R8
            ; pop R7
            ; pop R6
            ; add rsp, 16
            ; pop RINSN
            // `EXIT` leaves the remaining budget in `RMETER`, convert back to the instruction
            // limit.
            ; add RMETER, [rsp + 16]
            ; add QWORD rbp => Frame[BYTE -1].calls_remaining, 1
            ; ret
        );

        start
    }

    fn call_imm(out: &mut Asm, base: usize, target_checked: DynamicLabel) -> *const u8 {
        let start = address(out, base, true);
        x64asm!(out
            ; push RINSN
            ; push RTEMP
            ; mov RTEMP, [rsp + 32]
            ;; validate_meter(out)
            ; mov RTEMP, [rsp]
            ; sub RTEMP, rbp => Frame[BYTE -1].text_section
            ; cmp RTEMP, rbp => Frame[BYTE -1].text_section_len
            ; jb =>target_checked
            ; mov RTEMP, [rsp + 32]
            ;; terminate(out, SIG_INVALID_INSN)
        );
        start
    }

    /// The `load`, `store_imm` and `store_reg` helpers.
    #[allow(clippy::type_complexity)]
    fn memory_accesses(
        out: &mut Asm,
        base: usize,
    ) -> (
        [[[*const u8; Reg::COUNT]; Reg::COUNT]; 4],
        [[*const u8; Reg::COUNT]; 4],
        [[[*const u8; Reg::COUNT]; Reg::COUNT]; 4],
    ) {
        let mut load = [[[std::ptr::null(); Reg::COUNT]; Reg::COUNT]; 4];
        let mut store_imm = [[std::ptr::null(); Reg::COUNT]; 4];
        let mut store_reg = [[[std::ptr::null(); Reg::COUNT]; Reg::COUNT]; 4];
        let failed = out.new_dynamic_label();
        for size_log2 in 0..4 {
            for dst in Reg::ALL {
                let d = usize::from(dst.0);
                store_imm[size_log2][d] = Self::store(out, base, size_log2, dst, None, failed);
                for src in Reg::ALL {
                    let s = usize::from(src.0);
                    load[size_log2][d][s] = Self::load(out, base, size_log2, dst, src, failed);
                    store_reg[size_log2][d][s] =
                        Self::store(out, base, size_log2, dst, Some(src), failed);
                }
            }
        }
        x64asm!(out
            ; =>failed
            // Running out of budget takes precedence over the error.
            ;; validate_meter(out)
            ;; terminate(out, SIG_PROGRAM_RESULT)
        );
        (load, store_imm, store_reg)
    }

    /// The helpers for `divide`.
    fn divides(out: &mut Asm, base: usize) -> [[[*const u8; Reg::COUNT]; Reg::COUNT]; 4] {
        let mut divide = [[[std::ptr::null(); Reg::COUNT]; Reg::COUNT]; 4];
        for is_div in [false, true] {
            for is_64 in [false, true] {
                let kind = &mut divide[is_div as usize | (is_64 as usize) << 1];
                for dst in Reg::ALL {
                    for src in Reg::ALL {
                        kind[dst.0 as usize][src.0 as usize] = address(out, base, true);
                        Self::div_mod(out, is_div, is_64, dst, src);
                    }
                }
            }
        }
        divide
    }

    fn entry_point(out: &mut Asm, base: usize) -> *const u8 {
        // Expects `rsi` to point at the `Frame`, and `RINSN` and `RMETER` to be initialized to
        // their namesakes.
        let start = address(out, base, true);
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
            ;; load_bpf_registers(out, RSI, reg_mask(&GPREG_MAP))
            ; call QWORD rbp => Frame[BYTE -1].start
            // `terminate` and exit leave the exit code in `al`, the address of the instruction
            // following the last one executed in `RTEMP`, and r0 is in, well, `rsi`.
            ;=>after_dispatch
            ; mov rsp, rbp
            ; pop rbp
            ; ret
        );

        start
    }

    /// SBPFv0 `CALL_IMM`: the immediate is the key of either a syscall or an internal function.
    fn v0_call_imm(out: &mut Asm, base: usize, call_internal: DynamicLabel) -> *const u8 {
        let start = address(out, base, true);
        let (within_budget, not_internal, failed) = (
            out.new_dynamic_label(),
            out.new_dynamic_label(),
            out.new_dynamic_label(),
        );
        x64asm!(out
            // `validate_meter`, with the address of the next instruction below the return
            // address and `invoke_support`'s target, as `temp` has the key.
            ; cmp [rsp + 16], RMETER
            ; jbe BYTE =>within_budget
            ;; terminate(out, SIG_EXCEEDED_MAX_INSTRUCTIONS)
            ; =>within_budget
        );
        let pushed = clobber_for_sysv64_call(out);
        // The address of the next instruction is above `pushed`, the return address and
        // `invoke_support`'s target.
        let next_insn = pushed.checked_add(16).unwrap();
        let needs_stack_alignment =
            sysv64_call_needs_stack_alignment(next_insn.checked_add(8).unwrap());
        x64asm!(out
            ; mov rdi, rax
            // `clobber_for_sysv64_call` has pushed `temp`.
            ; mov esi, [rsp + 8]
            // The third argument, `remaining`.
            ;; const { assert!(RMETER == RDX) }
            ; sub RMETER, [rsp + next_insn]
            ; shr RMETER, 3
            ; mov rcx, rbp => Frame[BYTE -1].function_registry
        );
        if needs_stack_alignment {
            x64asm!(out; sub rsp, 8);
        }
        debug_assert_sysv64_call_stack_alignment(out);
        x64asm!(out; call QWORD rbp => Frame[BYTE -1].call_dispatcher);
        if needs_stack_alignment {
            x64asm!(out; add rsp, 8);
        }
        x64asm!(out
            ; cmp dl, HostCallStatus::CallInternal as i8
            ; jne =>not_internal
            // The target for `call_internal`, which is a host address, replaces `RTEMP`.
            ; shl rax, 3
            ; add rax, rbp => Frame[BYTE -1].text_section
            ; mov [rsp + 8], rax
            ;; restore_from_sysv64_call(out)
            ; jmp =>call_internal
            ; =>not_internal
            // As in `syscall`, `rax` is the budget remaining.
            ;; const { assert!(SYSV64_PUSHED >> RTEMP == 1 | 1 << (RMETER - RTEMP)) }
            ; mov RTEMP, [rsp + next_insn]
            ; lea RTEMP, [RTEMP + rax * 8]
            ; mov [rsp], RTEMP
            ; cmp dl, HostCallStatus::Ok as i8
            ;; restore_from_sysv64_call(out)
            ; jne =>failed
            ; ret
            ; =>failed
            ; mov RTEMP, [rsp + 16]
            ;; terminate(out, SIG_PROGRAM_RESULT)
        );
        start
    }

    /// SBPFv0 `CALL_REG`: the immediate is the number of the register with the target.
    /// Returns the routine and the stubs it jumps to.
    fn callx_target(
        out: &mut Asm,
        base: usize,
        call_internal: DynamicLabel,
    ) -> (*const u8, *const u8) {
        // Each register's code takes the same space, which is what `lea` can scale by.
        const STUB_SIZE: usize = 8;
        let common = out.new_dynamic_label();
        let stubs = address(out, base, true);
        for &reg in &GPREG_MAP {
            let stub_start = out.offset().0;
            x64asm!(out
                ; mov RTEMP, Rq(reg)
                ; jmp =>common
                ; .align 8
            );
            assert_eq!(out.offset().0.checked_sub(stub_start).unwrap(), STUB_SIZE);
        }
        x64asm!(out
            ; =>common
            ; sub RTEMP, rbp => Frame[BYTE -1].text_section_host_to_vm
            ; jmp =>call_internal
        );
        let start = address(out, base, true);
        let invalid = out.new_dynamic_label();
        let stubs_start = stubs;
        let stubs = i32::try_from(stubs as usize).expect("supports in the first 2 GiB");
        let last_register = (GPREG_MAP.len() as i32).checked_sub(1).unwrap();
        x64asm!(out
            ; cmp RTEMP, last_register
            ; ja =>invalid
            ; lea RTEMP, [ DWORD stubs + RTEMP * 8 ]
            ; jmp RTEMP
            ; =>invalid
            // `invoke_support`'s target and the return address are on top.
            ; mov RTEMP, [rsp + 16]
            ;; validate_meter(out)
            ;; terminate(out, SIG_INVALID_INSN)
        );
        (start, stubs_start)
    }

    fn syscall(out: &mut Asm, base: usize) -> *const u8 {
        let start = address(out, base, true);
        validate_meter(out);
        // `vm.invoke_function` takes the arguments from `vm.registers`, where
        // `clobber_for_sysv64_call` spills them.
        let pushed = clobber_for_sysv64_call(out);
        // Also the return address and `invoke_support`'s target.
        let needs_stack_alignment =
            sysv64_call_needs_stack_alignment(pushed.checked_add(16).unwrap());
        x64asm!(out
            ; mov rdi, rax
            ; mov esi, [RTEMP - 4]
            // The third argument, `remaining`.
            ;; const { assert!(RMETER == RDX) }
            ; sub RMETER, RTEMP
            ; shr RMETER, 3
        );
        if needs_stack_alignment {
            x64asm!(out; sub rsp, 8);
        }
        debug_assert_sysv64_call_stack_alignment(out);
        x64asm!(out; call QWORD rbp => Frame[BYTE -1].call_dispatcher);
        if needs_stack_alignment {
            x64asm!(out; add rsp, 8);
        }
        let failed = out.new_dynamic_label();
        x64asm!(out
            // The syscall has consumed the budget even if it failed. `clobber_for_sysv64_call`
            // has pushed `temp` and `meter` last.
            ;; const { assert!(SYSV64_PUSHED >> RTEMP == 1 | 1 << (RMETER - RTEMP)) }
            ; mov RTEMP, [rsp + 8]
            ; lea RTEMP, [RTEMP + rax * 8]
            ; mov [rsp], RTEMP
            ; cmp dl, HostCallStatus::Ok as i8
            ;; restore_from_sysv64_call(out)
            ; jnz =>failed
            ; ret
            ; =>failed
            ;; terminate(out, SIG_PROGRAM_RESULT)
        );
        start
    }

    #[cfg(feature = "tracer")]
    fn trace(out: &mut Asm, base: usize) -> *const u8 {
        let start = address(out, base, true);
        let pushed = clobber_for_sysv64_call(out);
        store_bpf_registers(out, RAX, !SYSV64_CLOBBERED);
        let pc_slot = register_slot(Reg(GPREG_MAP.len() as u8));
        x64asm!(out
            ; sub RTEMP, rbp => Frame[BYTE -1].text_section
            ; shr RTEMP, 3
            ; dec RTEMP
            ; mov [rax + pc_slot], RTEMP
            ; mov rdi, rax
        );
        call_host_sysv64_function(out, pushed, push_register_trace as *const u8);
        restore_from_sysv64_call(out);
        x64asm!(out; ret);
        start
    }

    /// Load `1 << size_log2` bytes into `dst` from the address in `src` plus the offset of the
    /// instruction preceding the address in `RTEMP`. Jumps to `failed` if the access fails.
    fn load(
        out: &mut Asm,
        base: usize,
        size_log2: usize,
        dst: Reg,
        src: Reg,
        failed: DynamicLabel,
    ) -> *const u8 {
        let start = address(out, base, true);
        let function = match size_log2 {
            0 => load::<u8> as *const u8,
            1 => load::<u16> as *const u8,
            2 => load::<u32> as *const u8,
            3 => load::<u64> as *const u8,
            _ => unreachable!(),
        };
        let pushed = clobber_for_sysv64_call(out);
        // Spilling leaves the BPF registers as they are, until they are overwritten with the
        // arguments.
        x64asm!(out
            ; mov rsi, Rq(src)
            ; movsx rdx, WORD [RTEMP - 6]
            ; add rsi, rdx
            ; mov rdi, rax => Vm.memory_mapping
            ; lea rdx, rax => Vm.program_result
        );
        call_host_sysv64_function(out, pushed, function);
        // `restore_from_sysv64_call` reloads the clobbered registers from their slots.
        if SYSV64_CLOBBERED & 1 << u8::from(dst) != 0 {
            x64asm!(out
                ; mov rcx, rbp => Frame[BYTE -1].vm
                ; mov [rcx + register_slot(dst)], rax
            );
        } else {
            x64asm!(out; mov Rq(dst), rax);
        }
        x64asm!(out
            ; cmp dl, HostCallStatus::Ok as i8
            ;; restore_from_sysv64_call(out)
            ; jne =>failed
            ; ret
        );
        start
    }

    /// Store `1 << size_log2` bytes of `src`, or of the immediate if `None`, to the address in
    /// `dst` plus the offset of the instruction preceding the address in `RTEMP`. Jumps to
    /// `failed` if the access fails.
    fn store(
        out: &mut Asm,
        base: usize,
        size_log2: usize,
        dst: Reg,
        src: Option<Reg>,
        failed: DynamicLabel,
    ) -> *const u8 {
        let start = address(out, base, true);
        let function = match size_log2 {
            0 => store::<u8> as *const u8,
            1 => store::<u16> as *const u8,
            2 => store::<u32> as *const u8,
            3 => store::<u64> as *const u8,
            _ => unreachable!(),
        };
        let pushed = clobber_for_sysv64_call(out);
        // Spilling leaves the BPF registers as they are, until they are overwritten with the
        // arguments: `src` may be in `rsi`, which is why the value goes first.
        match src {
            Some(src) => x64asm!(out; mov rdx, Rq(src)),
            None => x64asm!(out; movsxd rdx, DWORD [RTEMP - 4]),
        }
        x64asm!(out
            ; mov rsi, Rq(dst)
            ; movsx rdi, WORD [RTEMP - 6]
            ; add rsi, rdi
            ; mov rdi, rax => Vm.memory_mapping
            ; lea rcx, rax => Vm.program_result
        );
        call_host_sysv64_function(out, pushed, function);
        x64asm!(out
           ; cmp dl, HostCallStatus::Ok as i8
           ;; restore_from_sysv64_call(out)
           ; jne =>failed
           ; ret
        );
        start
    }

    fn div_mod(out: &mut Asm, is_div: bool, is_64: bool, dst: Reg, src: Reg) {
        if is_64 {
            x64asm!(out; test Rq(src), Rq(src));
        } else {
            x64asm!(out; test Rd(src), Rd(src));
        }
        let non_zero = out.new_dynamic_label();
        x64asm!(out
            ; jnz =>non_zero
            ;; validate_meter(out)
            ;; terminate(out, SIG_DIVIDE_BY_ZERO)
            ; =>non_zero
            ; mov RTEMP, Rq(src)
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
        i = i.checked_add(1).unwrap();
    }
    mask
}

/// For addressing `EbpfVm` fields as `reg => Vm.field`. The layout does not depend on the context
/// object, which is only behind pointers.
type Vm = crate::vm::EbpfVm<'static, crate::static_analysis::DummyContextObject>;

/// General purpose registers not preserved across `sysv64` calls.
const SYSV64_CLOBBERED: u16 = reg_mask(&[RAX, RCX, RDX, RSI, RDI, R8, R9, R10, R11]);
/// The registers `clobber_for_sysv64_call` pushes, rather than spills into `vm.registers`.
const SYSV64_PUSHED: u16 = SYSV64_CLOBBERED & !reg_mask(&GPREG_MAP);

/// Where the code generated next in `out`, based at `base`, is going to run from.
fn address(out: &mut Asm, base: usize, align_for_call: bool) -> *const u8 {
    if align_for_call {
        x64asm!(out; .align 16);
    }
    base.wrapping_add(out.offset().0) as *const u8
}

/// Like the JIT templates' `terminate`.
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

/// Like the JIT templates' `bpf_validate_meter`.
fn validate_meter(out: &mut Asm) {
    let within_budget = out.new_dynamic_label();
    x64asm!(out
        ; cmp RTEMP, RMETER
        ; jbe BYTE =>within_budget
        ;; terminate(out, SIG_EXCEEDED_MAX_INSTRUCTIONS)
        ; =>within_budget
    );
}

/// Offset of the slot of `reg` in `EbpfVm::registers`.
fn register_slot(reg: Reg) -> i32 {
    (std::mem::offset_of!(Vm, registers) as i32)
        .checked_add(i32::from(reg.0).checked_mul(8).unwrap())
        .unwrap()
}

/// Call the host `function`, with `pushed` bytes pushed since `clobber_for_sysv64_call`'s caller
/// was invoked by `invoke_support`.
fn call_host_sysv64_function(out: &mut Asm, pushed: i32, function: *const u8) {
    // Also the return address and `invoke_support`'s target.
    let needs_stack_alignment = sysv64_call_needs_stack_alignment(pushed.checked_add(16).unwrap());
    x64asm!(out; mov rax, QWORD function as i64);
    if needs_stack_alignment {
        x64asm!(out; sub rsp, 8);
    }
    debug_assert_sysv64_call_stack_alignment(out);
    x64asm!(out; call rax);
    if needs_stack_alignment {
        x64asm!(out; add rsp, 8);
    }
}

/// Store the BPF registers in `mask` into `vm.registers`, with the `EbpfVm` at `vm`.
fn store_bpf_registers(out: &mut Asm, vm: u8, mask: u16) {
    for (i, &reg) in GPREG_MAP.iter().enumerate() {
        let bpfreg = Reg(i as u8);
        if mask & 1 << reg != 0 {
            x64asm!(out; mov [Rq(vm) + register_slot(bpfreg)], Rq(reg));
        }
    }
}

/// Load the BPF registers in `mask` from `vm.registers`, with the `EbpfVm` address in register
/// named by `vm`.
///
/// Only some of the registers may be used to store VM.
fn load_bpf_registers(out: &mut Asm, vm: u8, mask: u16) {
    assert!(vm == GPREG_MAP[0] || vm == RINSN || vm == RTEMP || vm == RMETER);
    for (i, &reg) in GPREG_MAP.iter().enumerate().rev() {
        let bpfreg = Reg(i as u8);
        if mask & 1 << reg != 0 {
            x64asm!(out; mov Rq(reg), [Rq(vm) + register_slot(bpfreg)]);
        }
    }
}

/// Save the registers that a `sysv64` host function call would clobber: the rest are pushed in
/// the order of their register numbers (for the internal registers that is `insn`, `temp`,
/// `meter`), the BPF registers are spilled into `vm.registers`. Leaves the `EbpfVm` in `rax`.
///
/// Returns the number of bytes pushed. The stack is not aligned for the call, see
/// `sysv64_call_needs_stack_alignment`. Does not touch the flags.
fn clobber_for_sysv64_call(out: &mut Asm) -> i32 {
    for reg in 0..16 {
        if SYSV64_PUSHED & 1 << reg != 0 {
            x64asm!(out; push Rq(reg));
        }
    }
    const { assert!(SYSV64_PUSHED & 1 << RAX != 0) };
    x64asm!(out; mov rax, rbp => Frame[BYTE -1].vm);
    store_bpf_registers(out, RAX, SYSV64_CLOBBERED);
    (SYSV64_PUSHED.count_ones() as i32).checked_mul(8).unwrap()
}

/// Does `rsp` need to be adjusted by 8 bytes for a host function call, given the number of bytes
/// pushed since the BPF code? The stack is always aligned in the BPF code.
const fn sysv64_call_needs_stack_alignment(pushed: i32) -> bool {
    pushed % 16 != 0
}

/// Trap if the stack is not aligned for a host function call.
fn debug_assert_sysv64_call_stack_alignment(out: &mut Asm) {
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

/// Trap if the stack is not aligned for a call of the BPF code, which is aligned past the return
/// address, unlike host functions. Changes the flags.
fn debug_assert_bpf_call_stack_alignment(out: &mut Asm) {
    #[cfg(feature = "codegen_debug")]
    {
        let (aligned, misaligned) = (out.new_dynamic_label(), out.new_dynamic_label());
        x64asm!(out
            ; test esp, 7
            ; jnz =>misaligned
            ; bt esp, 3
            ; jc =>aligned
            ; =>misaligned
            ; int3
            ; =>aligned
        );
    }
    #[cfg(not(feature = "codegen_debug"))]
    let _ = out;
}

/// Restore the registers saved by `clobber_for_sysv64_call`. Does not touch the flags.
fn restore_from_sysv64_call(out: &mut Asm) {
    x64asm!(out; mov rax, rbp => Frame[BYTE -1].vm);
    load_bpf_registers(out, RAX, SYSV64_CLOBBERED);
    for reg in (0..16).rev() {
        if SYSV64_PUSHED & 1 << reg != 0 {
            x64asm!(out; pop Rq(reg));
        }
    }
}

/// Returned by the host functions, in the registers the fields are named after.
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
    /// The SBPFv0 `CALL_IMM` is an internal call, see `dispatch_call`.
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

#[cfg(feature = "tracer")]
extern "sysv64" fn push_register_trace(
    vm: &mut crate::vm::EbpfVm<crate::static_analysis::DummyContextObject>,
) {
    vm.register_trace.push(vm.registers);
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
    // SAFETY:
    //
    // Contract from `mem::transmute_copy`: `T` must not be larger than `u64`, and the first
    // `size_of::<T>()` bytes of the `u64` must be a valid `T`.
    // Evidence: `store` is only instantiated for `u8` to `u64` (see the match above), for which
    // every bit pattern is valid, and on little endian the first bytes are the low ones, which
    // truncates as intended.
    let value = unsafe { std::mem::transmute_copy::<u64, T>(&value) };
    HostCallResult::new(mapping.store::<T>(value, vm_addr), result)
}

/// The address of the function to store into `Frame::call_dispatcher`.
///
/// `remaining` is the budget left after the `CALL_IMM` instruction itself.
pub(super) fn call_dispatcher<C: crate::vm::ContextObject>(version: SBPFVersion) -> *const u8 {
    if version.static_syscalls() {
        dispatch_syscall::<C> as *const u8
    } else {
        dispatch_call::<C> as *const u8
    }
}

/// The SBPFv0 `CALL_IMM`: syscalls are looked up first, then `internal_functions`.
///
/// A key in both only runs the syscall, whereas the old JIT and interpreter run the syscall and then
/// the internal function too. Loading an ELF rejects such collisions.
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
    // TODO: avoid the lookup on every syscall. Programs only ever run against a handful of
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

#[cfg(test)]
mod tests {
    use super::*;

    fn contains_address(code: &[u8], address: *const u8) -> bool {
        let push = [&[0x68][..], &(address as u32).to_le_bytes()].concat();
        code.windows(push.len()).any(|window| window == push)
    }

    fn template_opcode(op: u8, dst: u8, src: u8) -> TemplateOpcode {
        TemplateOpcode(op as u16 | (dst as u16) << 8 | (src as u16) << 12)
    }

    #[test]
    fn shared_by_all_versions() {
        let supports = SupportingCode::get();
        let divide = template_opcode(ebpf::DIV64_REG, 1, 2);
        let call_imm = template_opcode(ebpf::CALL_IMM, 0, 0);
        let divide_helper = supports.divide(true, true, Reg(1), Reg(2));
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

            // SAFETY:
            //
            // Contract from `slice::from_raw_parts`: the memory must be valid for reads of the
            // length, and not mutated while borrowed.
            // Evidence: a step is `1 << STEP_SIZE_LOG2` bytes of the interpreter buffer, which is
            // read-execute and never freed, and the opcode's step is within it.
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

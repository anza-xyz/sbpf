//! The helpers for `CALL_IMM` and `CALL_REG`: internal calls of BPF functions and syscalls.

use super::*;

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

    pub(super) fn call_imm(out: &mut Asm, base: u32) -> u32 {
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

    pub(super) fn callx(out: &mut Asm, base: u32) -> (u32, [u32; Reg::COUNT]) {
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
                ; .align STUB_SIZE
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
            // Scale part of SIB has to be a literal. Change both lines at the same time.
            ;; const { assert!(STUB_SIZE == 8) }
            ; lea rax, [ DWORD stubs + rax * 8 ]
            ; jmp rax

            ; =>invalid
            ;; validate_meter(out)
            ;; terminate(out, SIG_INVALID_INSN)
        );
        (v0_callx, callx)
    }

    pub(super) fn v0_call_imm(out: &mut Asm, base: u32) -> u32 {
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

    pub(super) fn syscall(out: &mut Asm, base: u32) -> u32 {
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

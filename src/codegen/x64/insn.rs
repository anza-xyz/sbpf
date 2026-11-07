//! The machine code for each of the BPF instructions.

use super::*;
use crate::codegen::generate::InterpreterGenerator;
use crate::codegen::templates::AuxTemplate;
use crate::codegen::SIG_INVALID_INSN;
use supporting_code::{AccessSize, DivOp, Width};

/// Set the flags for the comparison of the 64 bit operands.
///
/// `RTEMP` expected to hold address of the next BPF instruction (from `load_next_insn_addr`.)
fn compare_64<G: Generator + ?Sized>(out: &mut G, dst: Reg, src: Reg) {
    let op = out.opcode().op();
    let is_imm = (op & ebpf::BPF_X) != ebpf::BPF_X;
    let is_jset = (op & ebpf::BPF_ALU_OP_MASK) == ebpf::BPF_JSET;
    match (is_imm, is_jset) {
        (true, false) => x64asm!(out
            ; movsxd RTEMP, DWORD [ RTEMP - 4i8 ]
            ; cmp Rq(dst), RTEMP
        ),
        (true, true) => x64asm!(out
            ; movsxd RTEMP, DWORD [ RTEMP - 4i8 ]
            ; test Rq(dst), RTEMP
        ),
        (false, false) => x64asm!(out; cmp Rq(dst), Rq(src)),
        (false, true) => x64asm!(out; test Rq(dst), Rq(src)),
    }
}

/// Like `compare_64`, for the 32 bit operands.
fn compare_32<G: Generator + ?Sized>(out: &mut G, dst: Reg, src: Reg) {
    let op = out.opcode().op();
    let is_imm = (op & ebpf::BPF_X) != ebpf::BPF_X;
    let is_jset = (op & ebpf::BPF_ALU_OP_MASK) == ebpf::BPF_JSET;
    match (is_imm, is_jset) {
        (true, false) => x64asm!(out; cmp Rd(dst), DWORD [ RTEMP - 4i8 ]),
        (true, true) => x64asm!(out; test Rd(dst), DWORD [ RTEMP - 4i8 ]),
        (false, false) => x64asm!(out; cmp Rd(dst), Rd(src)),
        (false, true) => x64asm!(out; test Rd(dst), Rd(src)),
    }
}

/// Produce a template for a conditional jump, the flags of which are set by `compare`.
fn conditional_branch<G: Generator + ?Sized>(
    out: &mut G,
    dst: Reg,
    src: Reg,
    compare: impl FnOnce(&mut G, Reg, Reg),
) {
    let op = out.opcode().op();
    // OPTIMIZATION: comparisons between same registers have predetermined outcome.
    if (op & ebpf::BPF_X) == ebpf::BPF_X && dst == src {
        match op & ebpf::BPF_ALU_OP_MASK {
            ebpf::BPF_JEQ | ebpf::BPF_JGE | ebpf::BPF_JLE | ebpf::BPF_JSGE | ebpf::BPF_JSLE => {
                load_next_insn_addr(out);
                bpf_validate_meter(out);
                return out.bpf_taken_branch(true);
            }
            ebpf::BPF_JNE | ebpf::BPF_JGT | ebpf::BPF_JLT | ebpf::BPF_JSGT | ebpf::BPF_JSLT => {
                return;
            }
            _ => {}
        }
    }
    load_next_insn_addr(out);
    bpf_validate_meter(out);
    compare(out, dst, src);
    let fallthrough = out.new_dynamic_label();
    match op & ebpf::BPF_ALU_OP_MASK {
        ebpf::BPF_JEQ => x64asm!(out; jne BYTE =>fallthrough),
        ebpf::BPF_JGT => x64asm!(out; jbe BYTE =>fallthrough),
        ebpf::BPF_JGE => x64asm!(out; jb BYTE =>fallthrough),
        ebpf::BPF_JNE => x64asm!(out; je BYTE =>fallthrough),
        ebpf::BPF_JSET => x64asm!(out; jz BYTE =>fallthrough),
        ebpf::BPF_JSGT => x64asm!(out; jle BYTE =>fallthrough),
        ebpf::BPF_JSGE => x64asm!(out; jl BYTE =>fallthrough),
        ebpf::BPF_JLT => x64asm!(out; jae BYTE =>fallthrough),
        ebpf::BPF_JLE => x64asm!(out; ja BYTE =>fallthrough),
        ebpf::BPF_JSLT => x64asm!(out; jge BYTE =>fallthrough),
        ebpf::BPF_JSLE => x64asm!(out; jg BYTE =>fallthrough),
        _ => invalid_insn(out),
    }
    // `compare_64` clobbers `RTEMP` for the immediate operand.
    let is_imm = (op & ebpf::BPF_X) != ebpf::BPF_X;
    let is_64 = (op & ebpf::BPF_CLS_MASK) == ebpf::BPF_JMP64;
    // FIXME: do something about the bool argument here.
    out.bpf_taken_branch(!(is_imm && is_64));
    out.dynamic_label(fallthrough);
}

/// Terminate execution for an instruction that is not valid.
fn invalid_insn<G: Generator + ?Sized>(out: &mut G) {
    load_next_insn_addr(out);
    x64asm!(out; jmp ->sig_invalid_insn);
}

/// Sign-extend 32-bit result in `dst` to 64 bits if sBPF version requires this.
fn maybe_sign_extend_result<G: Generator + ?Sized>(out: &mut G, dst: Reg) {
    if !out.version().explicit_sign_extension_of_results() {
        x64asm!(out; movsxd Rq(dst), Rd(dst));
    }
}

/// `dst /= wtemp`
fn udiv32<G: Generator + ?Sized>(out: &mut G, dst: Reg) {
    x64asm!(out
        ; push rax
        ; push rdx
        ; xor edx, edx
        ; mov eax, Rd(dst)
        ; div WTEMP
        ; mov Rd(dst), eax
        ; pop rdx
        ; pop rax
    );
}

/// `dst %= wtemp`
fn urem32<G: Generator + ?Sized>(out: &mut G, dst: Reg) {
    x64asm!(out
        ; push rax
        ; push rdx
        ; xor edx, edx
        ; mov eax, Rd(dst)
        ; div WTEMP
        ; mov Rd(dst), edx
        ; pop rdx
        ; pop rax
    );
}

/// `dst /= rtemp`
fn udiv64<G: Generator + ?Sized>(out: &mut G, dst: Reg) {
    x64asm!(out
        ; push rax
        ; push rdx
        ; xor edx, edx
        ; mov rax, Rq(dst)
        ; div RTEMP
        ; mov Rq(dst), rax
        ; pop rdx
        ; pop rax
    );
}

/// `dst %= rtemp`
fn urem64<G: Generator + ?Sized>(out: &mut G, dst: Reg) {
    x64asm!(out
        ; push rax
        ; push rdx
        ; xor edx, edx
        ; mov rax, Rq(dst)
        ; div RTEMP
        ; mov Rq(dst), rdx
        ; pop rdx
        ; pop rax
    );
}

/// Build the code to execute the BPF instruction.
pub(in crate::codegen) fn bpf_insn<G: Generator + ?Sized>(out: &mut G) {
    #[cfg(feature = "tracer")]
    {
        load_next_insn_addr(out);
        invoke_support(out, SupportingCode::get().trace);
    }
    let opcode = out.opcode();
    let op = opcode.op();
    let version = out.version();
    let (Some(dst), Some(src)) = (opcode.dst(), opcode.src()) else {
        return invalid_insn(out);
    };

    match op {
        ebpf::NEG32 if !version.disable_neg() => x64asm!(out; neg Rd(dst)),
        ebpf::NEG64 if !version.disable_neg() => x64asm!(out; neg Rq(dst)),
        #[rustfmt::skip]
        ebpf::OR32_IMM |
        ebpf::OR32_REG => x64asm!(out; or Rd(dst), ALU_SRC32(src)),
        ebpf::OR64_IMM => x64asm!(out
            ; movsxd RTEMP, DWORD REL32_IMM
            ; or Rq(dst), RTEMP
        ),
        #[rustfmt::skip]
        // OPTIMIZATION: X | X = X
        ebpf::OR64_REG => if dst != src { x64asm!(out
            ; or Rq(dst), Rq(src)
        )},
        ebpf::HOR64_IMM if version.disable_lddw() => x64asm!(out
            ; mov WTEMP, ALU_SRC32(src)
            ; shl RTEMP, 32
            ; or Rq(dst), RTEMP
        ),
        #[rustfmt::skip]
        ebpf::AND32_IMM |
        ebpf::AND32_REG => x64asm!(out; and Rd(dst), ALU_SRC32(src)),
        #[rustfmt::skip]
        ebpf::AND64_IMM => x64asm!(out
            ; movsxd RTEMP, DWORD REL32_IMM
            ; and Rq(dst), RTEMP
        ),
        #[rustfmt::skip]
        // OPTIMIZATION: X & X = X
        ebpf::AND64_REG => if dst != src { x64asm!(out
            ; and Rq(dst), Rq(src)
        )},
        #[rustfmt::skip]
        ebpf::XOR32_IMM |
        ebpf::XOR32_REG => x64asm!(out; xor Rd(dst), ALU_SRC32(src)),
        ebpf::XOR64_IMM => x64asm!(out
            ; movsxd RTEMP, DWORD REL32_IMM
            ; xor Rq(dst), RTEMP
        ),
        ebpf::XOR64_REG => x64asm!(out; xor Rq(dst), Rq(src)),
        ebpf::MOV32_IMM => x64asm!(out; mov Rd(dst), ALU_SRC32(src)),
        ebpf::MOV64_IMM => x64asm!(out; movsxd Rq(dst), ALU_SRC32(src)),
        ebpf::MOV32_REG => {
            if version.explicit_sign_extension_of_results() {
                x64asm!(out; movsxd Rq(dst), Rd(src))
            } else {
                x64asm!(out; mov Rd(dst), Rd(src))
            }
        }
        #[rustfmt::skip]
        // OPTIMIZATION: no-op move
        ebpf::MOV64_REG => if src != dst { x64asm!(out
            ; mov Rq(dst), Rq(src)
        )},

        ebpf::ADD64_REG => x64asm!(out; add Rq(dst), Rq(src)),
        ebpf::SUB64_REG => x64asm!(out; sub Rq(dst), Rq(src)),
        ebpf::MUL64_REG if !version.enable_pqr() => x64asm!(out; imul Rq(dst), Rq(src)),
        ebpf::ADD64_IMM => x64asm!(out
            ; movsxd RTEMP, REL32_IMM
            ; add Rq(dst), RTEMP
        ),
        ebpf::SUB64_IMM => {
            if version.swap_sub_reg_imm_operands() {
                x64asm!(out
                    ; neg Rq(dst)
                    ; movsxd RTEMP, DWORD REL32_IMM
                    ; add Rq(dst), RTEMP
                )
            } else {
                x64asm!(out
                    ; movsxd RTEMP, REL32_IMM
                    ; sub Rq(dst), RTEMP
                )
            }
        }
        ebpf::MUL64_IMM if !version.enable_pqr() => x64asm!(out
            ; movsxd RTEMP, REL32_IMM
            ; imul Rq(dst), RTEMP
        ),
        ebpf::ADD32_IMM | ebpf::ADD32_REG => x64asm!(out
            ; add Rd(dst), ALU_SRC32(src)
            ;; maybe_sign_extend_result(out, dst)
        ),
        ebpf::SUB32_IMM => {
            if version.swap_sub_reg_imm_operands() {
                x64asm!(out
                    ; neg Rd(dst)
                    ; add Rd(dst), DWORD REL32_IMM
                    ;; maybe_sign_extend_result(out, dst)
                )
            } else {
                x64asm!(out
                    ; sub Rd(dst), DWORD REL32_IMM
                    ;; maybe_sign_extend_result(out, dst)
                )
            }
        }
        ebpf::SUB32_REG => x64asm!(out
            ; sub Rd(dst), Rd(src)
            ;; maybe_sign_extend_result(out, dst)
        ),
        ebpf::MUL32_IMM | ebpf::MUL32_REG if !version.enable_pqr() => x64asm!(out
            ; imul Rd(dst), ALU_SRC32(src)
            ;; maybe_sign_extend_result(out, dst)
        ),
        #[rustfmt::skip]
        ebpf::DIV32_REG |
        ebpf::MOD32_REG |
        ebpf::DIV64_REG |
        ebpf::MOD64_REG if !version.enable_pqr() => {
            let div_op = match op & ebpf::BPF_ALU_OP_MASK {
                ebpf::BPF_DIV => DivOp::Div,
                _ => DivOp::Mod,
            };
            let width = match op & ebpf::BPF_CLS_MASK {
                ebpf::BPF_ALU64_STORE => Width::W64,
                _ => Width::W32,
            };
            let helper = SupportingCode::get().divide.get(div_op, width, dst, src);
            load_next_insn_addr(out);
            invoke_support(out, helper);
        }
        #[rustfmt::skip]
        ebpf::UDIV32_REG |
        ebpf::UREM32_REG |
        ebpf::UDIV64_REG |
        ebpf::UREM64_REG if version.enable_pqr() => {
            let div_op = match op {
                ebpf::UDIV32_REG | ebpf::UDIV64_REG => DivOp::Div,
                _ => DivOp::Mod,
            };
            let width = match op {
                ebpf::UDIV64_REG | ebpf::UREM64_REG => Width::W64,
                _ => Width::W32,
            };
            let helper = SupportingCode::get().divide.get(div_op, width, dst, src);
            load_next_insn_addr(out);
            invoke_support(out, helper);
        }
        ebpf::DIV32_IMM if !version.enable_pqr() => {
            x64asm!(out; mov WTEMP, DWORD REL32_IMM);
            udiv32(out, dst);
        }
        ebpf::UDIV32_IMM if version.enable_pqr() => {
            x64asm!(out; mov WTEMP, DWORD REL32_IMM);
            udiv32(out, dst);
        }
        ebpf::MOD32_IMM if !version.enable_pqr() => {
            x64asm!(out; mov WTEMP, DWORD REL32_IMM);
            urem32(out, dst);
        }
        ebpf::UREM32_IMM if version.enable_pqr() => {
            x64asm!(out; mov WTEMP, DWORD REL32_IMM);
            urem32(out, dst);
        }
        ebpf::DIV64_IMM if !version.enable_pqr() => {
            x64asm!(out; movsxd RTEMP, DWORD REL32_IMM);
            udiv64(out, dst);
        }
        ebpf::UDIV64_IMM if version.enable_pqr() => {
            x64asm!(out; mov WTEMP, DWORD REL32_IMM);
            udiv64(out, dst);
        }
        ebpf::MOD64_IMM if !version.enable_pqr() => {
            x64asm!(out; movsxd RTEMP, DWORD REL32_IMM);
            urem64(out, dst);
        }
        ebpf::UREM64_IMM if version.enable_pqr() => {
            x64asm!(out; mov WTEMP, DWORD REL32_IMM);
            urem64(out, dst);
        }
        ebpf::LSH64_REG => x64asm!(out; shlx Rq(dst), Rq(dst), Rq(src)),
        ebpf::LSH32_REG => x64asm!(out; shlx Rd(dst), Rd(dst), Rd(src)),
        ebpf::RSH64_REG => x64asm!(out; shrx Rq(dst), Rq(dst), Rq(src)),
        ebpf::RSH32_REG => x64asm!(out; shrx Rd(dst), Rd(dst), Rd(src)),
        ebpf::ARSH64_REG => x64asm!(out; sarx Rq(dst), Rq(dst), Rq(src)),
        ebpf::ARSH32_REG => x64asm!(out; sarx Rd(dst), Rd(dst), Rd(src)),
        ebpf::LSH64_IMM => x64asm!(out
            ;; const { assert!(RTEMP == RCX) }
            ; mov cl, BYTE REL32_IMM
            ; shl Rq(dst), cl
        ),
        ebpf::LSH32_IMM => x64asm!(out
            ;; const { assert!(RTEMP == RCX) }
            ; mov cl, BYTE REL32_IMM
            ; shl Rd(dst), cl
        ),
        ebpf::RSH64_IMM => x64asm!(out
            ;; const { assert!(RTEMP == RCX) }
            ; mov cl, BYTE REL32_IMM
            ; shr Rq(dst), cl
        ),
        ebpf::RSH32_IMM => x64asm!(out
            ;; const { assert!(RTEMP == RCX) }
            ; mov cl, BYTE REL32_IMM
            ; shr Rd(dst), cl
        ),
        ebpf::ARSH64_IMM => x64asm!(out
            ;; const { assert!(RTEMP == RCX) }
            ; mov cl, BYTE REL32_IMM
            ; sar Rq(dst), cl
        ),
        ebpf::ARSH32_IMM => x64asm!(out
            ;; const { assert!(RTEMP == RCX) }
            ; mov cl, BYTE REL32_IMM
            ; sar Rd(dst), cl
        ),
        ebpf::BE => x64asm!(out
            ; xor ecx, ecx
            ; bswap Rq(dst)
            // `BE` has `BPF_X` set, yet the operation width is always in the immediate.
            ; sub cl, BYTE REL32_IMM
            ; shr Rq(dst), cl
        ),
        ebpf::LE if !version.disable_le() => x64asm!(out
            ; mov WTEMP, ALU_SRC32(src)
            ; bzhi Rq(dst), Rq(dst), RTEMP
        ),

        ebpf::LMUL32_IMM | ebpf::LMUL32_REG if version.enable_pqr() => {
            x64asm!(out; imul Rd(dst), ALU_SRC32(src))
        }
        ebpf::LMUL64_IMM if version.enable_pqr() => x64asm!(out
            ; movsxd RTEMP, DWORD REL32_IMM
            ; imul Rq(dst), RTEMP
        ),
        ebpf::LMUL64_REG if version.enable_pqr() => x64asm!(out; imul Rq(dst), Rq(src)),
        ebpf::UHMUL64_IMM if version.enable_pqr() => x64asm!(out
            ; push rdx
            ; mov edx, DWORD REL32_IMM
            ; mulx Rq(dst), Rq(dst), Rq(dst)
            ; pop rdx
        ),
        ebpf::UHMUL64_REG if version.enable_pqr() => x64asm!(out
            ; push rdx
            ; mov rdx, Rq(dst)
            ; mulx Rq(dst), Rq(dst), Rq(src)
            ; pop rdx
        ),
        ebpf::SHMUL64_IMM if version.enable_pqr() => x64asm!(out
            ; movsxd RTEMP, DWORD REL32_IMM
            ; push rax
            ; push rdx
            ; mov rax, Rq(dst)
            ; imul RTEMP
            ; mov Rq(dst), rdx
            ; pop rdx
            ; pop rax
        ),
        ebpf::SHMUL64_REG if version.enable_pqr() => x64asm!(out
            ; push rax
            ; push rdx
            ; mov rax, Rq(dst)
            ; imul Rq(src)
            ; mov Rq(dst), rdx
            ; pop rdx
            ; pop rax
        ),
        #[rustfmt::skip]
        ebpf::SDIV32_IMM |
        ebpf::SDIV32_REG |
        ebpf::SDIV64_IMM |
        ebpf::SDIV64_REG |
        ebpf::SREM32_IMM |
        ebpf::SREM32_REG |
        ebpf::SREM64_IMM |
        ebpf::SREM64_REG if version.enable_pqr() => {
            let div_op = match op {
                ebpf::SDIV32_IMM | ebpf::SDIV32_REG | ebpf::SDIV64_IMM | ebpf::SDIV64_REG => {
                    DivOp::Div
                }
                _ => DivOp::Mod,
            };
            let width = match op {
                ebpf::SDIV64_IMM | ebpf::SDIV64_REG | ebpf::SREM64_IMM | ebpf::SREM64_REG => {
                    Width::W64
                }
                _ => Width::W32,
            };
            let divide = &SupportingCode::get().divide;
            let helper = if (op & ebpf::BPF_X) == ebpf::BPF_X {
                divide.get_signed(div_op, width, dst, src)
            } else {
                divide.get_signed_imm(div_op, width, dst)
            };
            load_next_insn_addr(out);
            invoke_support(out, helper);
        }

        ebpf::JEQ32_REG
        | ebpf::JGT32_REG
        | ebpf::JGE32_REG
        | ebpf::JLT32_REG
        | ebpf::JLE32_REG
        | ebpf::JNE32_REG
        | ebpf::JSET32_REG
        | ebpf::JSGT32_REG
        | ebpf::JSGE32_REG
        | ebpf::JSLT32_REG
        | ebpf::JSLE32_REG
        | ebpf::JEQ32_IMM
        | ebpf::JGT32_IMM
        | ebpf::JGE32_IMM
        | ebpf::JLT32_IMM
        | ebpf::JLE32_IMM
        | ebpf::JNE32_IMM
        | ebpf::JSET32_IMM
        | ebpf::JSGT32_IMM
        | ebpf::JSGE32_IMM
        | ebpf::JSLT32_IMM
        | ebpf::JSLE32_IMM
            if version.enable_jmp32() =>
        {
            conditional_branch(out, dst, src, compare_32)
        }
        ebpf::JLE64_IMM
        | ebpf::JEQ64_IMM
        | ebpf::JGT64_IMM
        | ebpf::JGE64_IMM
        | ebpf::JLT64_IMM
        | ebpf::JNE64_IMM
        | ebpf::JSET64_IMM
        | ebpf::JSLT64_IMM
        | ebpf::JSGE64_IMM
        | ebpf::JSGT64_IMM
        | ebpf::JSLE64_IMM
        | ebpf::JEQ64_REG
        | ebpf::JGT64_REG
        | ebpf::JGE64_REG
        | ebpf::JLT64_REG
        | ebpf::JLE64_REG
        | ebpf::JNE64_REG
        | ebpf::JSET64_REG
        | ebpf::JSGT64_REG
        | ebpf::JSGE64_REG
        | ebpf::JSLT64_REG
        | ebpf::JSLE64_REG => conditional_branch(out, dst, src, compare_64),
        ebpf::JA => {
            load_next_insn_addr(out);
            bpf_validate_meter(out);
            out.bpf_taken_branch(true);
        }

        ebpf::CALL_IMM => {
            load_next_insn_addr(out);
            out.meter_checked();
            match (version.static_syscalls(), src.0) {
                (false, _) => invoke_support(out, SupportingCode::get().v0v1v2_call_imm),
                (true, 1) => invoke_support(out, SupportingCode::get().call_imm),
                (true, 0) => invoke_support(out, SupportingCode::get().syscall),
                (true, _) => x64asm!(out; jmp ->sig_invalid_insn),
            }
        }
        ebpf::CALL_REG => {
            load_next_insn_addr(out);
            out.meter_checked();
            if version.callx_uses_src_reg() {
                invoke_support(out, SupportingCode::get().callx[usize::from(src.0)]);
            } else if version.callx_uses_dst_reg() {
                invoke_support(out, SupportingCode::get().callx[usize::from(dst.0)]);
            } else {
                invoke_support(out, SupportingCode::get().v0v1_callx);
            }
        }
        ebpf::EXIT => {
            load_next_insn_addr(out);
            bpf_validate_meter(out);
            x64asm!(out
                ; sub RMETER, RTEMP
                ; xor eax, eax
                ; ret
            );
        }

        ebpf::LD_DW_IMM if !version.disable_lddw() => {
            // The second half is another instruction with the more significant half of the
            // immediate.
            //
            // Counts as a single instruction, which moves the limit by one more slot. That's only
            // right once the instruction is within the budget, which means we gotta emit additional
            // code to check meter here.
            load_next_insn_addr(out);
            bpf_validate_meter(out);
            x64asm!(out
                ; add RMETER, BYTE ebpf::INSN_SIZE as i8
                ; mov Rd(dst), DWORD [RTEMP - 4]
                ; mov WTEMP, DWORD [RTEMP + 4]
                ; shl RTEMP, 32
                ; or Rq(dst), RTEMP
            )
        }

        ebpf::LD_B_REG
        | ebpf::LD_H_REG
        | ebpf::LD_W_REG
        | ebpf::LD_DW_REG
        | ebpf::ST_B_IMM
        | ebpf::ST_H_IMM
        | ebpf::ST_W_IMM
        | ebpf::ST_DW_IMM
        | ebpf::ST_B_REG
        | ebpf::ST_H_REG
        | ebpf::ST_W_REG
        | ebpf::ST_DW_REG
            if !version.move_memory_instruction_classes() =>
        {
            let size = AccessSize::of(op);
            let memory = &SupportingCode::get().memory;
            let helper = match op & ebpf::BPF_CLS_MASK {
                ebpf::BPF_LDX => memory.load(size, dst, src),
                ebpf::BPF_ST => memory.store_imm(size, dst),
                ebpf::BPF_STX => memory.store_reg(size, dst, src),
                _ => unreachable!(),
            };
            load_next_insn_addr(out);
            invoke_support(out, helper);
        }
        ebpf::LD_1B_REG
        | ebpf::LD_2B_REG
        | ebpf::LD_4B_REG
        | ebpf::LD_8B_REG
        | ebpf::ST_1B_IMM
        | ebpf::ST_2B_IMM
        | ebpf::ST_4B_IMM
        | ebpf::ST_8B_IMM
        | ebpf::ST_1B_REG
        | ebpf::ST_2B_REG
        | ebpf::ST_4B_REG
        | ebpf::ST_8B_REG
            if version.move_memory_instruction_classes() =>
        {
            let size = AccessSize::of_v2_opcode(op);
            let memory = &SupportingCode::get().memory;
            let helper = match (op & ebpf::BPF_CLS_MASK, op & ebpf::BPF_X) {
                (ebpf::BPF_ALU32_LOAD, _) => memory.load(size, dst, src),
                (_, ebpf::BPF_K) => memory.store_imm(size, dst),
                (_, _) => memory.store_reg(size, dst, src),
            };
            load_next_insn_addr(out);
            invoke_support(out, helper);
        }

        _ => invalid_insn(out),
    }
}

/// Generate the `AuxTemplate` `template`.
pub(in crate::codegen) fn aux_template<G: Generator + ?Sized>(out: &mut G, template: AuxTemplate) {
    match template {
        AuxTemplate::ExecutionOverrun => {
            load_next_insn_addr(out);
            bpf_validate_meter(out);
            terminate(out, SIG_EXECUTION_OVERRUN);
        }
        AuxTemplate::InvalidCallTarget => {
            // The code paths that might end up here are expected to update `next_insn`.
            x64asm!(out; mov RTEMP, rbp => Frame[BYTE -1].next_insn);
            #[cfg(feature = "tracer")]
            invoke_support(out, SupportingCode::get().trace);
            terminate_invalid_insn_with_meter_check(out);
        }
        AuxTemplate::Noop => x64asm!(out; nop),
        AuxTemplate::MeterCheckpoint => {
            load_next_insn_addr(out);
            bpf_validate_meter(out);
        }
    }
}

/// Terminate due to encountering an invalid instruction.
///
/// However if the execution was already exceeded at this point, terminate with that instead. The
/// returned value is an offset to the code that terminates for this reason.
fn terminate_invalid_insn_with_meter_check<G: Generator + ?Sized>(out: &mut G) -> usize {
    let exceeded = out.new_dynamic_label();
    x64asm!(out
        ; cmp RTEMP, RMETER
        ; ja BYTE =>exceeded
        ;; terminate(out, SIG_INVALID_INSN)
        ; =>exceeded
    );
    let offset = out.offset();
    terminate(out, SIG_EXCEEDED_MAX_INSTRUCTIONS);
    offset
}

/// Generate an island, returning the offsets of its entries from its start.
pub(in crate::codegen) fn island<G: Generator + ?Sized>(out: &mut G) -> IslandEntries {
    let start = out.offset();
    let end = out.new_dynamic_label();
    x64asm!(out; jmp BYTE =>end);
    let sig_invalid_insn = out.offset();
    let sig_meter_exceeded = terminate_invalid_insn_with_meter_check(out);
    out.dynamic_label(end);
    let mut entries = [0; IslandEntry::COUNT];
    entries[IslandEntry::SigInvalidInsn as usize] = sig_invalid_insn.wrapping_sub(start);
    entries[IslandEntry::SigMeterExceeded as usize] = sig_meter_exceeded.wrapping_sub(start);
    entries
}

/// [`Generator::bpf_taken_branch`] for JIT templates.
pub(in crate::codegen) fn jit_taken_branch<G: Generator + ?Sized>(
    out: &mut G,
    next_insn_in_temp: bool,
) {
    adjust_meter_for_taken_branch(out, next_insn_in_temp);
    x64asm!(out; jmp ->template_taken_branch);
}

/// [`Generator::bpf_taken_branch`] for interpreter steps.
pub(in crate::codegen) fn interpreter_taken_branch<G: Generator + ?Sized>(
    out: &mut G,
    next_insn_in_temp: bool,
) {
    adjust_meter_for_taken_branch(out, next_insn_in_temp);
    x64asm!(out; lea RINSN, [ RINSN + RTEMP*8 ]);
}

/// Move the limit in `RMETER` by the offset of the branch being taken.
///
/// Clobbers `RTEMP` with the offset field of the instruction.
fn adjust_meter_for_taken_branch<G: Generator + ?Sized>(out: &mut G, next_insn_in_temp: bool) {
    if next_insn_in_temp {
        x64asm!(out; movsx RTEMP, WORD [ RTEMP - 6i8 ]);
    } else {
        x64asm!(out; movsx RTEMP, WORD REL32_OFF);
    }
    x64asm!(out; lea RMETER, [ RMETER + RTEMP*8 ]);
}

/// Generate the epilogue of an interpreter step.
///
/// Dispatches to the step of the next instruction.
pub(in crate::codegen) fn interpreter_dispatch(out: &mut InterpreterGenerator) {
    let base_addr = i32::try_from(out.base() as usize).expect("interpreter in first 2GB");
    // `insn` points at the last 8 bytes of the instruction just executed.
    let size = i8::try_from(ebpf::opcode_size(out.opcode().op(), out.version())).unwrap();
    let to_last = size.checked_sub(8).unwrap();
    let next_insn = if size == 8 {
        RINSN
    } else {
        x64asm!(out; lea RTEMP, [ BYTE to_last + RINSN ]);
        RTEMP
    };
    // Unlike the JIT, the interpreter checks the meter after every instruction. This has little
    // impact on the throughput. Overrun has to be checked here as there is no code after the last
    // instruction to catch it.
    let overrun = out.new_dynamic_label();
    x64asm!(out
        ; cmp Rq(next_insn), RMETER
        ; jae ->sig_meter_exceeded
        ; cmp Rq(next_insn), rbp => Frame[BYTE -1].text_section_limit
        ; jae BYTE =>overrun
        ; movzx RTEMP, WORD [ BYTE to_last + RINSN ]
        ; shl RTEMP, InterpreterGenerator::STEP_SIZE_LOG2 as i8
        ; lea RTEMP, [ DWORD base_addr + RTEMP ]
        ; add RINSN, BYTE size
        ; jmp RTEMP
        ; =>overrun
        ; lea RTEMP, [ BYTE size + RINSN ]
        ;; terminate(out, SIG_EXECUTION_OVERRUN)
    );
}

/// Load the address of the BPF instruction following the current one into `RTEMP`.
fn load_next_insn_addr<G: Generator + ?Sized>(out: &mut G) {
    x64asm!(out
        ; lea RTEMP, [ DWORD 0i32 + RINSN ]
        ;; out.template_reloc(TemplateRelocationKind::InsnOffset, 0, 4, 0, ABSOLUTE_DWORD)
    );
}

/// Call the support at `support_addr`.
fn invoke_support<G: Generator + ?Sized>(out: &mut G, support_addr: u32) {
    // Every other register holds something, so `RINSN` makes room for the target. The JIT code
    // does not need to be within reach of a 32-bit displacement from the supports.
    x64asm!(out
        ; push RINSN
        ; mov eax, DWORD support_addr as i32
        ; call rax
        ; pop RINSN
    );
}

/// Terminate execution with the specified code.
///
/// Unless `code` is `SIG_EXCEEDED_MAX_INSTRUCTIONS`, `RTEMP` must contain the address of the
/// BPF instruction following the one terminating the execution.
///
/// This discards the guest stack and returns the exit code in `al`, the remaining budget
/// in `RMETER` and the address of the instruction following the faulting one in `RTEMP`.
pub(super) fn terminate<G: Generator + ?Sized>(out: &mut G, code: i8) {
    if code == SIG_EXCEEDED_MAX_INSTRUCTIONS {
        // The faulting instruction is the one at the limit rather than the one where the meter was
        // checked.
        x64asm!(out; lea RTEMP, [RMETER + 8]);
    } else {
        x64asm!(out; sub RMETER, RTEMP);
    }
    x64asm!(out
        ; mov al, code
        ; jmp QWORD rbp => Frame[BYTE -1].exit
    );
}

/// Terminate the execution if the instruction budget has been exceeded.
///
/// `RTEMP` must contain the address of the next BPF instruction.
pub(super) fn bpf_validate_meter<G: Generator + ?Sized>(out: &mut G) {
    out.meter_checked();
    x64asm!(out
        ; cmp RTEMP, RMETER
        ; ja ->sig_meter_exceeded
    );
}

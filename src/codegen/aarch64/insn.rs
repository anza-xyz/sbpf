//! The machine code for each of the BPF instructions.

use super::*;
use crate::codegen::generate::InterpreterGenerator;
use crate::codegen::host::AccessSize;
use crate::codegen::templates::AuxTemplate;
use crate::codegen::{
    SIG_DIVIDE_BY_ZERO, SIG_EXCEEDED_MAX_INSTRUCTIONS, SIG_EXECUTION_OVERRUN, SIG_INVALID_INSN,
};

/// Load `addend` plus the offset from `RINSN` to the current BPF instruction into `W(reg)`.
fn insn_offset<G: Generator + ?Sized>(out: &mut G, reg: u8, addend: i32) {
    let addend = addend as u32;
    a64asm!(out
        ; movz W(reg), addend & 0xffff
        ; movk W(reg), addend >> 16, lsl 16
    );
    out.template_reloc(TemplateRelocationKind::InsnOffset, 0, 8, 0, 0);
}

/// Load the address of the BPF instruction following the current one into `RTEMP`.
fn load_next_insn_addr<G: Generator + ?Sized>(out: &mut G) {
    insn_offset(out, RTEMP, 0);
    a64asm!(out; add RTEMP, RINSN, WTEMP, sxtw);
}

/// Load the immediate of the current BPF instruction into `reg`, sign or zero extended.
fn load_imm<G: Generator + ?Sized>(out: &mut G, reg: u8, sign_extend: bool) {
    insn_offset(out, RFIELD, -4);
    if sign_extend {
        a64asm!(out; ldrsw X(reg), [RINSN, WFIELD, sxtw]);
    } else {
        a64asm!(out; ldr W(reg), [RINSN, WFIELD, sxtw]);
    }
}

/// The register with the 32-bit source operand of the ALU instruction: `src`, or `RFIELD` loaded
/// with the immediate for the `_IMM` instructions.
fn alu_src32<G: Generator + ?Sized>(out: &mut G, src: Reg) -> u8 {
    if (out.opcode().op() & ebpf::BPF_X) == ebpf::BPF_X {
        u8::from(src)
    } else {
        load_imm(out, RFIELD, false);
        RFIELD
    }
}

/// Set the flags for the comparison of the 64 bit operands.
///
/// `RTEMP` expected to hold address of the next BPF instruction (from `load_next_insn_addr`.)
fn compare_64<G: Generator + ?Sized>(out: &mut G, dst: Reg, src: Reg) {
    let op = out.opcode().op();
    let is_imm = (op & ebpf::BPF_X) != ebpf::BPF_X;
    let is_jset = (op & ebpf::BPF_ALU_OP_MASK) == ebpf::BPF_JSET;
    let src = if is_imm {
        a64asm!(out; ldursw RFIELD, [RTEMP, -4]);
        RFIELD
    } else {
        u8::from(src)
    };
    if is_jset {
        a64asm!(out; tst X(dst), X(src));
    } else {
        a64asm!(out; cmp X(dst), X(src));
    }
}

/// Like `compare_64`, for the 32 bit operands.
fn compare_32<G: Generator + ?Sized>(out: &mut G, dst: Reg, src: Reg) {
    let op = out.opcode().op();
    let is_imm = (op & ebpf::BPF_X) != ebpf::BPF_X;
    let is_jset = (op & ebpf::BPF_ALU_OP_MASK) == ebpf::BPF_JSET;
    let src = if is_imm {
        a64asm!(out; ldur WFIELD, [RTEMP, -4]);
        RFIELD
    } else {
        u8::from(src)
    };
    if is_jset {
        a64asm!(out; tst W(dst), W(src));
    } else {
        a64asm!(out; cmp W(dst), W(src));
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
        ebpf::BPF_JEQ => a64asm!(out; b.ne =>fallthrough),
        ebpf::BPF_JGT => a64asm!(out; b.ls =>fallthrough),
        ebpf::BPF_JGE => a64asm!(out; b.lo =>fallthrough),
        ebpf::BPF_JNE => a64asm!(out; b.eq =>fallthrough),
        ebpf::BPF_JSET => a64asm!(out; b.eq =>fallthrough),
        ebpf::BPF_JSGT => a64asm!(out; b.le =>fallthrough),
        ebpf::BPF_JSGE => a64asm!(out; b.lt =>fallthrough),
        ebpf::BPF_JLT => a64asm!(out; b.hs =>fallthrough),
        ebpf::BPF_JLE => a64asm!(out; b.hi =>fallthrough),
        ebpf::BPF_JSLT => a64asm!(out; b.ge =>fallthrough),
        ebpf::BPF_JSLE => a64asm!(out; b.gt =>fallthrough),
        _ => return invalid_insn(out),
    }
    out.bpf_taken_branch(true);
    out.dynamic_label(fallthrough);
}

/// Terminate execution for an instruction that is not valid.
///
/// Jumps to the supporting code directly rather than to the island, as that needs no relocation.
fn invalid_insn<G: Generator + ?Sized>(out: &mut G) {
    load_next_insn_addr(out);
    jump_to_support(out, Support::Signal(SIG_INVALID_INSN));
}

/// `DIV*_REG` and `MOD*_REG`.
fn divide_by_reg<G: Generator + ?Sized>(out: &mut G, dst: Reg, src: Reg) {
    let op = out.opcode().op();
    let is_div = (op & ebpf::BPF_ALU_OP_MASK) == ebpf::BPF_DIV;
    load_next_insn_addr(out);
    let (dst, src) = (u8::from(dst), u8::from(src));
    match ((op & ebpf::BPF_CLS_MASK) == ebpf::BPF_ALU64_STORE, is_div) {
        (true, true) => a64asm!(out
            ; cbz X(src), ->sig_divide_by_zero
            ; udiv X(dst), X(dst), X(src)
        ),
        (true, false) => a64asm!(out
            ; cbz X(src), ->sig_divide_by_zero
            ; udiv RFIELD, X(dst), X(src)
            ; msub X(dst), RFIELD, X(src), X(dst)
        ),
        (false, true) => a64asm!(out
            ; cbz W(src), ->sig_divide_by_zero
            ; udiv W(dst), W(dst), W(src)
        ),
        (false, false) => a64asm!(out
            ; cbz W(src), ->sig_divide_by_zero
            ; udiv WFIELD, W(dst), W(src)
            ; msub W(dst), WFIELD, W(src), W(dst)
        ),
    }
}

/// `DIV*_IMM` and `MOD*_IMM`. The verifier rejects zero immediates, so there's no need to check
/// those.
fn divide_by_imm<G: Generator + ?Sized>(out: &mut G, dst: Reg) {
    let op = out.opcode().op();
    let is_div = (op & ebpf::BPF_ALU_OP_MASK) == ebpf::BPF_DIV;
    let is_64 = (op & ebpf::BPF_CLS_MASK) == ebpf::BPF_ALU64_STORE;
    load_imm(out, RFIELD, is_64);
    let dst = u8::from(dst);
    match (is_64, is_div) {
        (true, true) => a64asm!(out; udiv X(dst), X(dst), RFIELD),
        (true, false) => a64asm!(out
            ; udiv x0, X(dst), RFIELD
            ; msub X(dst), x0, RFIELD, X(dst)
        ),
        (false, true) => a64asm!(out; udiv W(dst), W(dst), WFIELD),
        (false, false) => a64asm!(out
            ; udiv w0, W(dst), WFIELD
            ; msub W(dst), w0, WFIELD, W(dst)
        ),
    }
}

/// Build the code to execute the BPF instruction.
pub(in crate::codegen) fn bpf_insn<G: Generator + ?Sized>(out: &mut G) {
    #[cfg(feature = "tracer")]
    {
        load_next_insn_addr(out);
        invoke_support(out, Support::Trace);
    }
    let opcode = out.opcode();
    let op = opcode.op();
    let (Some(dst), Some(src)) = (opcode.dst(), opcode.src()) else {
        return invalid_insn(out);
    };
    let (d, s) = (u8::from(dst), u8::from(src));

    match op {
        ebpf::NEG32 => a64asm!(out; neg W(d), W(d)),
        ebpf::NEG64 => a64asm!(out; neg X(d), X(d)),
        ebpf::OR32_IMM | ebpf::OR32_REG => {
            let s = alu_src32(out, src);
            a64asm!(out; orr W(d), W(d), W(s))
        }
        ebpf::OR64_IMM => {
            load_imm(out, RFIELD, true);
            a64asm!(out; orr X(d), X(d), RFIELD)
        }
        // OPTIMIZATION: X | X = X
        ebpf::OR64_REG => {
            if dst != src {
                a64asm!(out; orr X(d), X(d), X(s))
            }
        }
        ebpf::HOR64_IMM => {
            if out.version().disable_lddw() {
                load_imm(out, RFIELD, false);
                a64asm!(out; orr X(d), X(d), RFIELD, lsl 32)
            } else {
                invalid_insn(out)
            }
        }
        ebpf::AND32_IMM | ebpf::AND32_REG => {
            let s = alu_src32(out, src);
            a64asm!(out; and W(d), W(d), W(s))
        }
        ebpf::AND64_IMM => {
            load_imm(out, RFIELD, true);
            a64asm!(out; and X(d), X(d), RFIELD)
        }
        // OPTIMIZATION: X & X = X
        ebpf::AND64_REG => {
            if dst != src {
                a64asm!(out; and X(d), X(d), X(s))
            }
        }
        ebpf::XOR32_IMM | ebpf::XOR32_REG => {
            let s = alu_src32(out, src);
            a64asm!(out; eor W(d), W(d), W(s))
        }
        ebpf::XOR64_IMM => {
            load_imm(out, RFIELD, true);
            a64asm!(out; eor X(d), X(d), RFIELD)
        }
        ebpf::XOR64_REG => a64asm!(out; eor X(d), X(d), X(s)),
        ebpf::MOV32_IMM => load_imm(out, d, false),
        ebpf::MOV64_IMM => load_imm(out, d, true),
        ebpf::MOV32_REG => a64asm!(out; mov W(d), W(s)),
        // OPTIMIZATION: no-op move
        ebpf::MOV64_REG => {
            if dst != src {
                a64asm!(out; mov X(d), X(s))
            }
        }

        ebpf::ADD64_REG => a64asm!(out; add X(d), X(d), X(s)),
        ebpf::SUB64_REG => a64asm!(out; sub X(d), X(d), X(s)),
        ebpf::MUL64_REG => a64asm!(out; mul X(d), X(d), X(s)),
        ebpf::ADD64_IMM => {
            load_imm(out, RFIELD, true);
            a64asm!(out; add X(d), X(d), RFIELD)
        }
        ebpf::SUB64_IMM => {
            load_imm(out, RFIELD, true);
            a64asm!(out; sub X(d), X(d), RFIELD)
        }
        ebpf::MUL64_IMM => {
            load_imm(out, RFIELD, true);
            a64asm!(out; mul X(d), X(d), RFIELD)
        }
        ebpf::ADD32_IMM | ebpf::ADD32_REG => {
            let s = alu_src32(out, src);
            a64asm!(out
                ; add W(d), W(d), W(s)
                ; sxtw X(d), W(d)
            )
        }
        ebpf::SUB32_IMM | ebpf::SUB32_REG => {
            let s = alu_src32(out, src);
            a64asm!(out
                ; sub W(d), W(d), W(s)
                ; sxtw X(d), W(d)
            )
        }
        ebpf::MUL32_IMM | ebpf::MUL32_REG => {
            let s = alu_src32(out, src);
            a64asm!(out
                ; mul W(d), W(d), W(s)
                ; sxtw X(d), W(d)
            )
        }
        ebpf::DIV32_REG | ebpf::MOD32_REG | ebpf::DIV64_REG | ebpf::MOD64_REG => {
            divide_by_reg(out, dst, src)
        }
        ebpf::DIV32_IMM | ebpf::MOD32_IMM | ebpf::DIV64_IMM | ebpf::MOD64_IMM => {
            divide_by_imm(out, dst)
        }
        ebpf::LSH64_REG => a64asm!(out; lsl X(d), X(d), X(s)),
        ebpf::LSH32_REG => a64asm!(out; lsl W(d), W(d), W(s)),
        ebpf::RSH64_REG => a64asm!(out; lsr X(d), X(d), X(s)),
        ebpf::RSH32_REG => a64asm!(out; lsr W(d), W(d), W(s)),
        ebpf::ARSH64_REG => a64asm!(out; asr X(d), X(d), X(s)),
        ebpf::ARSH32_REG => a64asm!(out; asr W(d), W(d), W(s)),
        ebpf::LSH64_IMM => {
            load_imm(out, RFIELD, false);
            a64asm!(out; lsl X(d), X(d), RFIELD)
        }
        ebpf::LSH32_IMM => {
            load_imm(out, RFIELD, false);
            a64asm!(out; lsl W(d), W(d), WFIELD)
        }
        ebpf::RSH64_IMM => {
            load_imm(out, RFIELD, false);
            a64asm!(out; lsr X(d), X(d), RFIELD)
        }
        ebpf::RSH32_IMM => {
            load_imm(out, RFIELD, false);
            a64asm!(out; lsr W(d), W(d), WFIELD)
        }
        ebpf::ARSH64_IMM => {
            load_imm(out, RFIELD, false);
            a64asm!(out; asr X(d), X(d), RFIELD)
        }
        ebpf::ARSH32_IMM => {
            load_imm(out, RFIELD, false);
            a64asm!(out; asr W(d), W(d), WFIELD)
        }
        ebpf::BE => {
            // `BE` has `BPF_X` set, yet the operation width is always in the immediate. Shifts
            // take the amount modulo 64, so shifting by the negated width shifts by `64 - width`.
            load_imm(out, RFIELD, false);
            a64asm!(out
                ; rev X(d), X(d)
                ; neg WFIELD, WFIELD
                ; lsr X(d), X(d), RFIELD
            )
        }
        ebpf::LE => {
            // Shifting by the negated width, as for `BE`.
            load_imm(out, RFIELD, false);
            a64asm!(out
                ; neg WFIELD, WFIELD
                ; lsl X(d), X(d), RFIELD
                ; lsr X(d), X(d), RFIELD
            )
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
        | ebpf::JSLE32_IMM => {
            if out.version().enable_jmp32() {
                conditional_branch(out, dst, src, compare_32)
            } else {
                invalid_insn(out)
            }
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
            match (out.version().static_syscalls(), src.0) {
                (false, _) => invoke_support(out, Support::V0CallImm),
                (true, 1) => invoke_support(out, Support::CallImm),
                (true, 0) => invoke_support(out, Support::Syscall),
                (true, _) => jump_to_support(out, Support::Signal(SIG_INVALID_INSN)),
            }
        }
        ebpf::CALL_REG => {
            load_next_insn_addr(out);
            out.meter_checked();
            if out.version().callx_uses_dst_reg() {
                a64asm!(out; mov x0, X(d));
                invoke_support(out, Support::Callx);
            } else {
                invoke_support(out, Support::V0Callx);
            }
        }
        ebpf::EXIT => {
            load_next_insn_addr(out);
            bpf_validate_meter(out);
            // The caller pushed the return address, see `call_bpf_function`.
            a64asm!(out
                ; sub RMETER, RMETER, RTEMP
                ; mov w0, 0
                ; ldr x30, [sp], 16
                ; ret
            );
        }

        ebpf::LD_DW_IMM => {
            // The second half is another instruction with the more significant half of the
            // immediate.
            //
            // Counts as a single instruction, which moves the limit by one more slot. That's only
            // right once the instruction is within the budget, which means we gotta emit additional
            // code to check meter here.
            load_next_insn_addr(out);
            bpf_validate_meter(out);
            a64asm!(out
                ; add RMETER, RMETER, ebpf::INSN_SIZE as u32
                ; ldur W(d), [RTEMP, -4]
                ; ldur WFIELD, [RTEMP, 4]
                ; orr X(d), X(d), RFIELD, lsl 32
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
        | ebpf::ST_DW_REG => {
            let size = AccessSize::of(op);
            load_next_insn_addr(out);
            match op & ebpf::BPF_CLS_MASK {
                ebpf::BPF_LDX => {
                    a64asm!(out; mov x1, X(s));
                    invoke_support(out, Support::Load(size));
                    a64asm!(out; mov X(d), x0);
                }
                ebpf::BPF_ST => {
                    a64asm!(out; mov x1, X(d));
                    invoke_support(out, Support::StoreImm(size));
                }
                ebpf::BPF_STX => {
                    a64asm!(out
                        ; mov x1, X(d)
                        ; mov x2, X(s)
                    );
                    invoke_support(out, Support::StoreReg(size));
                }
                _ => unreachable!(),
            }
        }

        _ => invalid_insn(out),
    }
}

/// Generate the `AuxTemplate` `template`.
pub(in crate::codegen) fn aux_template<G: Generator + ?Sized>(out: &mut G, template: AuxTemplate) {
    match template {
        AuxTemplate::ExecutionOverrun => {
            load_next_insn_addr(out);
            jump_to_support(out, Support::Signal(SIG_EXECUTION_OVERRUN));
        }
        AuxTemplate::InvalidCallTarget => {
            // The code paths that might end up here are expected to update `next_insn`.
            a64asm!(out; ldr RTEMP, [RFRAME, frame_offset!(next_insn)]);
            #[cfg(feature = "tracer")]
            invoke_support(out, Support::Trace);
            jump_to_support(out, Support::Signal(SIG_INVALID_INSN));
        }
        AuxTemplate::Noop => a64asm!(out; nop),
        AuxTemplate::MeterCheckpoint => {
            load_next_insn_addr(out);
            bpf_validate_meter(out);
        }
    }
}

/// Generate an island, returning the offsets of its entries from its start.
pub(in crate::codegen) fn island<G: Generator + ?Sized>(out: &mut G) -> IslandEntries {
    let start = out.offset();
    let end = out.new_dynamic_label();
    let mut entries = [0; IslandEntry::COUNT];
    a64asm!(out; b =>end);
    for (entry, support) in [
        (
            IslandEntry::SigInvalidInsn,
            Support::Signal(SIG_INVALID_INSN),
        ),
        (
            IslandEntry::SigMeterExceeded,
            Support::Signal(SIG_EXCEEDED_MAX_INSTRUCTIONS),
        ),
        (
            IslandEntry::SigDivideByZero,
            Support::Signal(SIG_DIVIDE_BY_ZERO),
        ),
        (IslandEntry::FarJump, Support::FarJump),
    ] {
        entries[entry as usize] = out.offset().checked_sub(start).unwrap();
        jump_to_support(out, support);
    }
    out.dynamic_label(end);
    entries
}

/// [`Generator::bpf_taken_branch`] for JIT templates.
pub(in crate::codegen) fn jit_taken_branch<G: Generator + ?Sized>(
    out: &mut G,
    next_insn_in_temp: bool,
) {
    assert!(
        next_insn_in_temp,
        "far jumps need the next instruction in `RTEMP`"
    );
    adjust_meter_for_taken_branch(out, next_insn_in_temp);
    a64asm!(out; b ->template_taken_branch);
}

/// [`Generator::bpf_taken_branch`] for interpreter steps.
pub(in crate::codegen) fn interpreter_taken_branch<G: Generator + ?Sized>(
    out: &mut G,
    next_insn_in_temp: bool,
) {
    adjust_meter_for_taken_branch(out, next_insn_in_temp);
    a64asm!(out; add RINSN, RINSN, RFIELD, lsl 3);
}

/// Move the limit in `RMETER` by the offset of the branch being taken.
///
/// Leaves the offset field of the instruction in `RFIELD`.
fn adjust_meter_for_taken_branch<G: Generator + ?Sized>(out: &mut G, next_insn_in_temp: bool) {
    if next_insn_in_temp {
        a64asm!(out; ldursh RFIELD, [RTEMP, -6]);
    } else {
        insn_offset(out, RFIELD, -6);
        a64asm!(out; ldrsh RFIELD, [RINSN, WFIELD, sxtw]);
    }
    a64asm!(out; add RMETER, RMETER, RFIELD, lsl 3);
}

/// Generate the epilogue of an interpreter step.
///
/// Dispatches to the step of the next instruction.
pub(in crate::codegen) fn interpreter_dispatch(out: &mut InterpreterGenerator) {
    // `RINSN` points at the last 8 bytes of the instruction just executed.
    let size = u32::try_from(ebpf::opcode_size(out.opcode().op())).unwrap();
    let to_last = size.checked_sub(8).unwrap();
    let next_insn = if size == 8 {
        RINSN
    } else {
        a64asm!(out; add RFIELD, RINSN, to_last);
        RFIELD
    };
    // Unlike the JIT, the interpreter checks the meter after every instruction. This has little
    // impact on the throughput. Overrun has to be checked here as there is no code after the last
    // instruction to catch it.
    //
    // Both are checked with a single branch, as more branches in the step slow the dispatch down.
    let stop = out.new_dynamic_label();
    a64asm!(out
        ; ldr x0, [RFRAME, frame_offset!(text_section_limit)]
        ; cmp X(next_insn), RMETER
        // If the meter is exceeded, set the carry flag so that `hs` holds.
        ; ccmp X(next_insn), x0, 0b0010, lo
        ; b.hs =>stop
        ; ldrh WTARGET, [RINSN, to_last]
        ; add RINSN, RINSN, size
        ; add RTARGET, RCODE, RTARGET, lsl InterpreterGenerator::STEP_SIZE_LOG2 as u32
        ; br RTARGET
        ; =>stop
        ; cmp X(next_insn), RMETER
        ; b.hs ->sig_meter_exceeded
        ; add RTEMP, RINSN, size
        ;; jump_to_support(out, Support::Signal(SIG_EXECUTION_OVERRUN))
    );
}

/// Call the supporting function `support`.
fn invoke_support<G: Generator + ?Sized>(out: &mut G, support: Support) {
    a64asm!(out
        ; ldr RTARGET, [RSUPPORTS, support.table_offset()]
        ; blr RTARGET
    );
}

/// Continue in the supporting function `support`.
fn jump_to_support<G: Generator + ?Sized>(out: &mut G, support: Support) {
    a64asm!(out
        ; ldr RTARGET, [RSUPPORTS, support.table_offset()]
        ; br RTARGET
    );
}

/// Terminate the execution if the instruction budget has been exceeded.
///
/// `RTEMP` must contain the address of the next BPF instruction.
fn bpf_validate_meter<G: Generator + ?Sized>(out: &mut G) {
    out.meter_checked();
    a64asm!(out
        ; cmp RTEMP, RMETER
        ; b.hi ->sig_meter_exceeded
    );
}

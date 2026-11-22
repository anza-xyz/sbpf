//! RV64 instruction selection for the shared interpreter steps and JIT templates.

use super::*;
use crate::codegen::generate::InterpreterGenerator;
use crate::codegen::host::AccessSize;
use crate::codegen::templates::AuxTemplate;
use crate::codegen::{
    SIG_DIVIDE_BY_ZERO, SIG_EXCEEDED_MAX_INSTRUCTIONS, SIG_EXECUTION_OVERRUN, SIG_INVALID_INSN,
};

/// Form an instruction field address relative to RINSN. In the interpreter RINSN already points
/// after the current instruction. The JIT also patches in the PC and its random bias.
fn insn_address<G: Generator + ?Sized>(out: &mut G, reg: u8, addend: i32) {
    rv_asm!(out
        ; lui X(reg), 0
        ; addiw X(reg), X(reg), addend
    );
    out.template_reloc(TemplateRelocationKind::InsnOffset, 0, 8, 0, 0);
    rv_asm!(out; add X(reg), X(reg), RINSN);
}

fn load_next_insn_addr<G: Generator + ?Sized>(out: &mut G) {
    insn_address(out, RTEMP, 0);
}

fn load_imm<G: Generator + ?Sized>(out: &mut G, reg: u8, signed: bool) {
    insn_address(out, RFIELD, -4);
    if signed {
        rv_asm!(out; lw X(reg), [RFIELD]);
    } else {
        rv_asm!(out; lwu X(reg), [RFIELD]);
    }
}

fn zero_extend_word<G: Generator + ?Sized>(out: &mut G, dst: u8, src: u8) {
    rv_asm!(out
        ; slli X(dst), X(src), 32
        ; srli X(dst), X(dst), 32
    );
}

/// RV64 W arithmetic sign extends naturally. Logical and shift instructions, along with
/// unsigned division and remainder, need the unsigned low word as the guest result.
fn binary_alu<G: Generator + ?Sized>(out: &mut G, dst: u8, src: u8) {
    let op = out.opcode().op();
    let word = op & ebpf::BPF_CLS_MASK == ebpf::BPF_ALU32_LOAD;
    let operation = op & ebpf::BPF_ALU_OP_MASK;
    let reg_src = op & ebpf::BPF_X != 0;
    let divisor = matches!(operation, ebpf::BPF_DIV | ebpf::BPF_MOD);
    let src = if reg_src {
        if divisor {
            load_next_insn_addr(out);
            let nonzero = out.new_dynamic_label();
            if word {
                rv_asm!(out; addiw RFIELD, X(src), 0; bne RFIELD, zero, =>nonzero);
            } else {
                rv_asm!(out; bne X(src), zero, =>nonzero);
            }
            rv_asm!(out; jal zero, ->sig_divide_by_zero; =>nonzero);
        }
        src
    } else {
        // The verifier rejects a zero immediate divisor.
        load_imm(out, RFIELD, !word);
        RFIELD
    };
    match (word, operation) {
        (false, ebpf::BPF_ADD) => rv_asm!(out; add X(dst), X(dst), X(src)),
        (false, ebpf::BPF_SUB) => rv_asm!(out; sub X(dst), X(dst), X(src)),
        (false, ebpf::BPF_MUL) => rv_asm!(out; mul X(dst), X(dst), X(src)),
        (false, ebpf::BPF_DIV) => rv_asm!(out; divu X(dst), X(dst), X(src)),
        (false, ebpf::BPF_MOD) => rv_asm!(out; remu X(dst), X(dst), X(src)),
        (false, ebpf::BPF_LSH) => rv_asm!(out; sll X(dst), X(dst), X(src)),
        (false, ebpf::BPF_RSH) => rv_asm!(out; srl X(dst), X(dst), X(src)),
        (false, ebpf::BPF_ARSH) => rv_asm!(out; sra X(dst), X(dst), X(src)),
        (true, ebpf::BPF_ADD) => return rv_asm!(out; addw X(dst), X(dst), X(src)),
        (true, ebpf::BPF_SUB) => return rv_asm!(out; subw X(dst), X(dst), X(src)),
        (true, ebpf::BPF_MUL) => return rv_asm!(out; mulw X(dst), X(dst), X(src)),
        (true, ebpf::BPF_DIV) => rv_asm!(out; divuw X(dst), X(dst), X(src)),
        (true, ebpf::BPF_MOD) => rv_asm!(out; remuw X(dst), X(dst), X(src)),
        (true, ebpf::BPF_LSH) => rv_asm!(out; sllw X(dst), X(dst), X(src)),
        (true, ebpf::BPF_RSH) => rv_asm!(out; srlw X(dst), X(dst), X(src)),
        (true, ebpf::BPF_ARSH) => rv_asm!(out; sraw X(dst), X(dst), X(src)),
        (_, ebpf::BPF_OR) => rv_asm!(out; or X(dst), X(dst), X(src)),
        (_, ebpf::BPF_AND) => rv_asm!(out; and X(dst), X(dst), X(src)),
        (_, ebpf::BPF_XOR) => rv_asm!(out; xor X(dst), X(dst), X(src)),
        _ => unreachable!(),
    }
    if word {
        zero_extend_word(out, dst, dst);
    }
}

/// Only the low word participates in a JMP32. Sign extending *both* words preserves their
/// unsigned ordering for BLTU/BGEU as well as their signed ordering for BLT/BGE.
fn conditional_branch<G: Generator + ?Sized>(out: &mut G, dst: u8, src: u8, word: bool) {
    let op = out.opcode().op();
    load_next_insn_addr(out);
    bpf_validate_meter(out);
    const A0: u8 = 10;
    let lhs = if word {
        rv_asm!(out; addiw X(A0), X(dst), 0);
        A0
    } else {
        dst
    };
    let rhs = if op & ebpf::BPF_X == 0 {
        rv_asm!(out; lw RFIELD, [RTEMP, -4]);
        RFIELD
    } else if word {
        rv_asm!(out; addiw RFIELD, X(src), 0);
        RFIELD
    } else {
        src
    };
    let skip = out.new_dynamic_label();
    match op & ebpf::BPF_ALU_OP_MASK {
        ebpf::BPF_JEQ => rv_asm!(out; bne X(lhs), X(rhs), =>skip),
        ebpf::BPF_JNE => rv_asm!(out; beq X(lhs), X(rhs), =>skip),
        ebpf::BPF_JGT => rv_asm!(out; bgeu X(rhs), X(lhs), =>skip),
        ebpf::BPF_JGE => rv_asm!(out; bltu X(lhs), X(rhs), =>skip),
        ebpf::BPF_JLT => rv_asm!(out; bgeu X(lhs), X(rhs), =>skip),
        ebpf::BPF_JLE => rv_asm!(out; bltu X(rhs), X(lhs), =>skip),
        ebpf::BPF_JSGT => rv_asm!(out; bge X(rhs), X(lhs), =>skip),
        ebpf::BPF_JSGE => rv_asm!(out; blt X(lhs), X(rhs), =>skip),
        ebpf::BPF_JSLT => rv_asm!(out; bge X(lhs), X(rhs), =>skip),
        ebpf::BPF_JSLE => rv_asm!(out; blt X(rhs), X(lhs), =>skip),
        ebpf::BPF_JSET => rv_asm!(out; and RFIELD, X(lhs), X(rhs); beq RFIELD, zero, =>skip),
        _ => unreachable!(),
    }
    out.bpf_taken_branch(true);
    out.dynamic_label(skip);
}

fn invalid_insn<G: Generator + ?Sized>(out: &mut G) {
    load_next_insn_addr(out);
    jump_to_support(out, Support::Signal(SIG_INVALID_INSN));
}

/// Reverse the bytes without depending on Zbb. Shifting the full reversed value by the
/// negated width (modulo 64) gives the requested 16-, 32-, or 64-bit result.
fn big_endian<G: Generator + ?Sized>(out: &mut G, dst: u8) {
    load_imm(out, RFIELD, false);
    let next_byte = out.new_dynamic_label();
    rv_asm!(out
        ; addi a0, zero, 0
        ; addi a1, zero, 8
        ; =>next_byte
        ; andi a2, X(dst), 255
        ; slli a0, a0, 8
        ; or a0, a0, a2
        ; srli X(dst), X(dst), 8
        ; addi a1, a1, -1
        ; bne a1, zero, =>next_byte
        ; sub RFIELD, zero, RFIELD
        ; srl X(dst), a0, RFIELD
    );
}

/// Generate a single guest instruction for either execution mode.
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
        ebpf::NEG64 => rv_asm!(out; sub X(d), zero, X(d)),
        ebpf::NEG32 => {
            rv_asm!(out; subw X(d), zero, X(d));
            zero_extend_word(out, d, d);
        }
        ebpf::MOV32_IMM => load_imm(out, d, false),
        ebpf::MOV64_IMM => load_imm(out, d, true),
        ebpf::MOV32_REG => zero_extend_word(out, d, s),
        ebpf::MOV64_REG => {
            if d != s {
                rv_asm!(out; addi X(d), X(s), 0);
            }
        }
        ebpf::ADD32_IMM
        | ebpf::ADD32_REG
        | ebpf::ADD64_IMM
        | ebpf::ADD64_REG
        | ebpf::SUB32_IMM
        | ebpf::SUB32_REG
        | ebpf::SUB64_IMM
        | ebpf::SUB64_REG
        | ebpf::MUL32_IMM
        | ebpf::MUL32_REG
        | ebpf::MUL64_IMM
        | ebpf::MUL64_REG
        | ebpf::DIV32_IMM
        | ebpf::DIV32_REG
        | ebpf::DIV64_IMM
        | ebpf::DIV64_REG
        | ebpf::MOD32_IMM
        | ebpf::MOD32_REG
        | ebpf::MOD64_IMM
        | ebpf::MOD64_REG
        | ebpf::LSH32_IMM
        | ebpf::LSH32_REG
        | ebpf::LSH64_IMM
        | ebpf::LSH64_REG
        | ebpf::RSH32_IMM
        | ebpf::RSH32_REG
        | ebpf::RSH64_IMM
        | ebpf::RSH64_REG
        | ebpf::ARSH32_IMM
        | ebpf::ARSH32_REG
        | ebpf::ARSH64_IMM
        | ebpf::ARSH64_REG
        | ebpf::OR32_IMM
        | ebpf::OR32_REG
        | ebpf::OR64_IMM
        | ebpf::OR64_REG
        | ebpf::AND32_IMM
        | ebpf::AND32_REG
        | ebpf::AND64_IMM
        | ebpf::AND64_REG
        | ebpf::XOR32_IMM
        | ebpf::XOR32_REG
        | ebpf::XOR64_IMM
        | ebpf::XOR64_REG => {
            binary_alu(out, d, s);
        }
        ebpf::HOR64_IMM if out.version().disable_lddw() => {
            load_imm(out, RFIELD, false);
            rv_asm!(out; slli RFIELD, RFIELD, 32; or X(d), X(d), RFIELD);
        }
        ebpf::BE => big_endian(out, d),
        ebpf::LE => {
            load_imm(out, RFIELD, false);
            rv_asm!(out
                ; sub RFIELD, zero, RFIELD
                ; sll X(d), X(d), RFIELD
                ; srl X(d), X(d), RFIELD
            );
        }
        ebpf::JA => {
            load_next_insn_addr(out);
            bpf_validate_meter(out);
            out.bpf_taken_branch(true);
        }
        ebpf::JEQ32_REG
        | ebpf::JEQ32_IMM
        | ebpf::JNE32_REG
        | ebpf::JNE32_IMM
        | ebpf::JGT32_REG
        | ebpf::JGT32_IMM
        | ebpf::JGE32_REG
        | ebpf::JGE32_IMM
        | ebpf::JLT32_REG
        | ebpf::JLT32_IMM
        | ebpf::JLE32_REG
        | ebpf::JLE32_IMM
        | ebpf::JSGT32_REG
        | ebpf::JSGT32_IMM
        | ebpf::JSGE32_REG
        | ebpf::JSGE32_IMM
        | ebpf::JSLT32_REG
        | ebpf::JSLT32_IMM
        | ebpf::JSLE32_REG
        | ebpf::JSLE32_IMM
        | ebpf::JSET32_REG
        | ebpf::JSET32_IMM
            if out.version().enable_jmp32() =>
        {
            conditional_branch(out, d, s, true);
        }
        ebpf::JEQ64_REG
        | ebpf::JEQ64_IMM
        | ebpf::JNE64_REG
        | ebpf::JNE64_IMM
        | ebpf::JGT64_REG
        | ebpf::JGT64_IMM
        | ebpf::JGE64_REG
        | ebpf::JGE64_IMM
        | ebpf::JLT64_REG
        | ebpf::JLT64_IMM
        | ebpf::JLE64_REG
        | ebpf::JLE64_IMM
        | ebpf::JSGT64_REG
        | ebpf::JSGT64_IMM
        | ebpf::JSGE64_REG
        | ebpf::JSGE64_IMM
        | ebpf::JSLT64_REG
        | ebpf::JSLT64_IMM
        | ebpf::JSLE64_REG
        | ebpf::JSLE64_IMM
        | ebpf::JSET64_REG
        | ebpf::JSET64_IMM => conditional_branch(out, d, s, false),
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
                rv_asm!(out; addi a0, X(d), 0);
                invoke_support(out, Support::Callx);
            } else {
                invoke_support(out, Support::V0Callx);
            }
        }
        ebpf::EXIT => {
            load_next_insn_addr(out);
            bpf_validate_meter(out);
            rv_asm!(out
                ; sub RMETER, RMETER, RTEMP
                ; addi a0, zero, 0
                ; ld ra, [sp]
                ; addi sp, sp, 16
                ; ret
            );
        }
        ebpf::LD_DW_IMM => {
            load_next_insn_addr(out);
            bpf_validate_meter(out);
            rv_asm!(out
                ; addi RMETER, RMETER, 8
                ; lwu X(d), [RTEMP, -4]
                ; lw RFIELD, [RTEMP, 4]
                ; slli RFIELD, RFIELD, 32
                ; or X(d), X(d), RFIELD
            );
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
                    rv_asm!(out; addi a1, X(s), 0);
                    invoke_support(out, Support::Load(size));
                    rv_asm!(out; addi X(d), a0, 0);
                }
                ebpf::BPF_ST => {
                    rv_asm!(out; addi a1, X(d), 0);
                    invoke_support(out, Support::StoreImm(size));
                }
                ebpf::BPF_STX => {
                    rv_asm!(out; addi a1, X(d), 0; addi a2, X(s), 0);
                    invoke_support(out, Support::StoreReg(size));
                }
                _ => unreachable!(),
            }
        }
        _ => invalid_insn(out),
    }
}

pub(in crate::codegen) fn aux_template<G: Generator + ?Sized>(out: &mut G, template: AuxTemplate) {
    match template {
        AuxTemplate::ExecutionOverrun => {
            load_next_insn_addr(out);
            jump_to_support(out, Support::Signal(SIG_EXECUTION_OVERRUN));
        }
        AuxTemplate::InvalidCallTarget => {
            rv_asm!(out; ld RTEMP, [RFRAME, frame_offset!(next_insn)]);
            #[cfg(feature = "tracer")]
            invoke_support(out, Support::Trace);
            jump_to_support(out, Support::Signal(SIG_INVALID_INSN));
        }
        AuxTemplate::Noop => rv_asm!(out; nop),
        AuxTemplate::MeterCheckpoint => {
            load_next_insn_addr(out);
            bpf_validate_meter(out);
        }
    }
}

pub(in crate::codegen) fn island<G: Generator + ?Sized>(out: &mut G) -> IslandEntries {
    let start = out.offset();
    let end = out.new_dynamic_label();
    let mut entries = [0; IslandEntry::COUNT];
    rv_asm!(out; jal zero, =>end);
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

pub(in crate::codegen) fn jit_taken_branch<G: Generator + ?Sized>(
    out: &mut G,
    next_insn_in_temp: bool,
) {
    assert!(
        next_insn_in_temp,
        "far jumps need the next instruction in RTEMP"
    );
    adjust_meter_for_taken_branch(out);
    rv_asm!(out; jal zero, ->template_taken_branch);
}

pub(in crate::codegen) fn interpreter_taken_branch<G: Generator + ?Sized>(
    out: &mut G,
    next_insn_in_temp: bool,
) {
    assert!(next_insn_in_temp);
    adjust_meter_for_taken_branch(out);
    rv_asm!(out; add RINSN, RINSN, RFIELD);
}

fn adjust_meter_for_taken_branch<G: Generator + ?Sized>(out: &mut G) {
    rv_asm!(out
        ; lh RFIELD, [RTEMP, -6]
        ; slli RFIELD, RFIELD, 3
        ; add RMETER, RMETER, RFIELD
    );
}

/// Dispatch directly to the next step, checking the budget before an execution overrun.
pub(in crate::codegen) fn interpreter_dispatch(out: &mut InterpreterGenerator) {
    let size = i32::try_from(ebpf::opcode_size(out.opcode().op())).unwrap();
    let to_last = size.checked_sub(8).unwrap();
    let next_insn = if to_last != 0 {
        rv_asm!(out; addi RFIELD, RINSN, to_last);
        RFIELD
    } else {
        RINSN
    };
    let within_budget = out.new_dynamic_label();
    let overrun = out.new_dynamic_label();
    let step_shift = u32::from(InterpreterGenerator::STEP_SIZE_LOG2);
    rv_asm!(out
        ; bltu X(next_insn), RMETER, =>within_budget
        ; jal zero, ->sig_meter_exceeded
        ; =>within_budget
        ; ld a0, [RFRAME, frame_offset!(text_section_limit)]
        ; bgeu X(next_insn), a0, =>overrun
        ; lhu RTARGET, [RINSN, to_last]
        ; addi RINSN, RINSN, size
        ; slli RTARGET, RTARGET, step_shift
        ; add RTARGET, RCODE, RTARGET
        ; jr RTARGET
        ; =>overrun
        ; addi RTEMP, RINSN, size
    );
    jump_to_support(out, Support::Signal(SIG_EXECUTION_OVERRUN));
}

fn invoke_support<G: Generator + ?Sized>(out: &mut G, support: Support) {
    rv_asm!(out; ld RTARGET, [RSUPPORTS, support.table_offset()]; jalr ra, RTARGET, 0);
}

fn jump_to_support<G: Generator + ?Sized>(out: &mut G, support: Support) {
    rv_asm!(out; ld RTARGET, [RSUPPORTS, support.table_offset()]; jr RTARGET);
}

fn bpf_validate_meter<G: Generator + ?Sized>(out: &mut G) {
    out.meter_checked();
    let within_budget = out.new_dynamic_label();
    rv_asm!(out
        ; bgeu RMETER, RTEMP, =>within_budget
        ; jal zero, ->sig_meter_exceeded
        ; =>within_budget
    );
}

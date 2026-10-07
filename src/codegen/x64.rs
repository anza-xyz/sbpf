//! The x86_64 backend.

use super::generate::{self, Generator, InterpreterGenerator, PatchFields};
use super::*;
use dynasmrt::relocations::Relocation as _;
use dynasmrt::relocations::RelocationKind;
use std::convert::TryFrom;

/// The relocations of `dynasm` for x86_64.
pub(super) type Relocation = dynasmrt::x64::X64Relocation;

const RAX: u8 = 0;
const RCX: u8 = 1;
const RDX: u8 = 2;
const RBX: u8 = 3;
const RSI: u8 = 6;
const RDI: u8 = 7;
const R8: u8 = 8;
const R9: u8 = 9;
const R10: u8 = 10;
const R11: u8 = 11;

// Internal registers. Keep in sync with the `.alias`es in `x64asm!`.
#[allow(unused)]
const RINSN: u8 = RAX;
const RTEMP: u8 = RCX;
const RMETER: u8 = RDX;

/// Mapping from a numbered eBPF register to an x64 one.
///
/// Keep in sync with the `.alias`es in `x64asm!`.
const GPREG_MAP: [u8; 11] = [
    RSI, // r0 = rsi
    RDI, // r1 = rdi
    8,   // r2 = r8
    9,   // r3
    10,  // r4
    11,  // r5
    12,  // r6
    13,  // r7
    14,  // r8
    15,  // r9 = r15
    // NOTE: this is a pretty special read-only register which we could have a special case for
    // (likely at a significant expense of code complexity.) Dedicating an architectural register
    // for this feels like a shame. At the same time we can't make instructions involving r10 much
    // slower or produce significantly more code, because it would be an obvious target for resource
    // exploitation.
    RBX, // r10 = rbx
];

impl From<Reg> for u8 {
    /// The machine register for the BPF one, which is how `dynasm` takes the registers.
    fn from(reg: Reg) -> u8 {
        GPREG_MAP[reg.0 as usize]
    }
}

/// Is the value in the provided register disposable/temporary?
pub const fn disposable_reg(reg: u8) -> bool {
    reg == RTEMP
}

macro_rules! x64asm {
    ($output: expr; $($tts:tt)*) => { x64asm!(@munch {$output; [] []} ; $($tts)*) };
    (@munch {$output:expr; [$($acc:tt)*] [$($curr:tt)*]}) => {{
        #![allow(clippy::neg_multiply, clippy::useless_conversion)]
        dynasm::dynasm!($output
            ; .arch x64
            // BPF registers (see `GPREG_MAP`.)
            ; .alias R0, rsi
            ; .alias R1, rdi
            ; .alias R2, r8
            ; .alias R3, r9
            ; .alias R4, r10
            ; .alias R5, r11
            ; .alias R6, r12
            ; .alias R7, r13
            ; .alias R8, r14
            ; .alias R9, r15
            ; .alias R10, rbx
            // Internal registers.
            ; .alias RINSN, rax
            ; .alias RTEMP, rcx
            ; .alias WTEMP, ecx
            ; .alias RMETER, rdx
            $($acc)* $($curr)*
        )
    }};

    // replace ALU_SRC32(src) operand with either the source register for ALU instructions using
    // source register operand, or an immediate fetch for `_IMM` ALU instructions.
    (@munch {$output:expr; [$($acc:tt)*] [$($curr:tt)*]} ALU_SRC32($src:expr) $($rest:tt)*) => {
        x64asm!(@munch {$output; [ $($acc)* ] [ ; if ($output.opcode().op() & ebpf::BPF_X) == ebpf::BPF_X {
            x64asm!(@munch {$output; [;] [$($curr)*]} Rd($src))
          } else {
            x64asm!(@munch {$output; [;] [$($curr)*]} DWORD REL32_IMM)
          }
        ]} $($rest)*)
    };

    (@munch {$output:expr; [$($acc:tt)*] [$($curr:tt)*]} REL32_IMM $($rest:tt)*) => {
        x64asm!(@munch {$output; [ $($acc)* ] [
            $($curr)* [ DWORD -4i32 + RINSN ] ;; $output.template_reloc(TemplateRelocationKind::InsnOffset, -4, 4, 0, ABSOLUTE_DWORD)
        ]} $($rest)*)
    };

    (@munch {$output:expr; [$($acc:tt)*] [$($curr:tt)*]} REL32_OFF $($rest:tt)*) => {
        x64asm!(@munch {$output; [ $($acc)* ] [
            $($curr)* [ DWORD -6i32 + RINSN ] ;; $output.template_reloc(TemplateRelocationKind::InsnOffset, -6, 4, 0, ABSOLUTE_DWORD)
        ]} $($rest)*)
    };

    (@munch {$output:expr; [$($acc:tt)*] [$($curr:tt)*]} ; $($rest:tt)*) => {
        {
        // compile_error!(stringify!(semi x64asm!(@munch {$output; [$($acc)* ; $($curr)*] []} $($rest)*)));
        x64asm!(@munch {$output; [$($acc)* $($curr)* ;] []} $($rest)*)
        }
    };
    (@munch {$output:expr; [$($acc:tt)*] [$($curr:tt)*]} $tok:tt $($rest:tt)*) => {
        {
        // compile_error!(stringify!(last x64asm!(@munch {$output; [$($acc)*] [$($curr)* $tok]} $($rest)* )));
        x64asm!(@munch {$output; [$($acc)*] [$($curr)* $tok]} $($rest)* )
        }
    };
}

pub(super) mod supporting_code;
#[cfg(feature = "codegen-debug")]
pub(super) use supporting_code::SupportingCode;
#[cfg(not(feature = "codegen-debug"))]
use supporting_code::SupportingCode;

/// Set the flags for the comparison of the 64 bit registers (or the immediate) of the conditional
/// jump being generated.
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

/// Like `compare_64`, for the lower 32 bits.
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
                return out.bpf_taken_branch();
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
    out.bpf_taken_branch();
    out.dynamic_label(fallthrough);
}

/// Terminate execution for an instruction that is not valid.
fn invalid_insn<G: Generator + ?Sized>(out: &mut G) {
    load_next_insn_addr(out);
    x64asm!(out; jmp ->sig_invalid_insn);
}

/// Build the code to execute the BPF instruction.
pub(super) fn bpf_insn<G: Generator + ?Sized>(out: &mut G) {
    #[cfg(feature = "tracer")]
    {
        load_next_insn_addr(out);
        invoke_support(out, SupportingCode::get().trace);
    }
    let opcode = out.opcode();
    let op = opcode.op();
    let (Some(dst), Some(src)) = (opcode.dst(), opcode.src()) else {
        return invalid_insn(out);
    };
    let is_alu64 = (op & ebpf::BPF_CLS_MASK) == ebpf::BPF_ALU64_STORE;

    match op {
        ebpf::NEG32 => x64asm!(out; neg Rd(dst)),
        ebpf::NEG64 => x64asm!(out; neg Rq(dst)),
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
        ebpf::HOR64_IMM => {
            if out.version().disable_lddw() {
                x64asm!(out
                    ; mov WTEMP, ALU_SRC32(src)
                    ; shl RTEMP, 32
                    ; or Rq(dst), RTEMP
                )
            } else {
                invalid_insn(out)
            }
        }
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
        ebpf::MOV32_REG => x64asm!(out; mov Rd(dst), Rd(src)),
        #[rustfmt::skip]
        // OPTIMIZATION: no-op move
        ebpf::MOV64_REG => if src != dst { x64asm!(out
            ; mov Rq(dst), Rq(src)
        )},

        ebpf::ADD64_REG => x64asm!(out; add Rq(dst), Rq(src)),
        ebpf::SUB64_REG => x64asm!(out; sub Rq(dst), Rq(src)),
        ebpf::MUL64_REG => x64asm!(out; imul Rq(dst), Rq(src)),
        ebpf::ADD64_IMM => x64asm!(out
            ; movsxd RTEMP, REL32_IMM
            ; add Rq(dst), RTEMP
        ),
        ebpf::SUB64_IMM => x64asm!(out
            ; movsxd RTEMP, REL32_IMM
            ; sub Rq(dst), RTEMP
        ),
        ebpf::MUL64_IMM => x64asm!(out
            ; movsxd RTEMP, REL32_IMM
            ; imul Rq(dst), RTEMP
        ),
        ebpf::ADD32_IMM | ebpf::ADD32_REG => x64asm!(out
            ; add Rd(dst), ALU_SRC32(src)
            ; movsxd Rq(dst), Rd(dst)
        ),
        ebpf::SUB32_IMM | ebpf::SUB32_REG => x64asm!(out
            ; sub Rd(dst), ALU_SRC32(src)
            ; movsxd Rq(dst), Rd(dst)
        ),
        ebpf::MUL32_IMM | ebpf::MUL32_REG => x64asm!(out
            ; imul Rd(dst), ALU_SRC32(src)
            ; movsxd Rq(dst), Rd(dst)
        ),
        #[rustfmt::skip]
        ebpf::DIV32_REG |
        ebpf::MOD32_REG |
        ebpf::DIV64_REG |
        ebpf::MOD64_REG => {
            let is_div = (op & ebpf::BPF_ALU_OP_MASK) == ebpf::BPF_DIV;
            let helper = SupportingCode::get().divide(is_div, is_alu64, dst, src);
            load_next_insn_addr(out);
            invoke_support(out, helper);
        }
        // The verifier rejects zero immediates, so there's no need to check those.
        ebpf::DIV32_IMM => x64asm!(out
            ; mov WTEMP, DWORD REL32_IMM
            ; push rax
            ; push rdx
            ; xor edx, edx
            ; mov eax, Rd(dst)
            ; div WTEMP
            ; mov Rd(dst), eax
            ; pop rdx
            ; pop rax
        ),
        ebpf::MOD32_IMM => x64asm!(out
            ; mov WTEMP, DWORD REL32_IMM
            ; push rax
            ; push rdx
            ; xor edx, edx
            ; mov eax, Rd(dst)
            ; div WTEMP
            ; mov Rd(dst), edx
            ; pop rdx
            ; pop rax
        ),
        ebpf::DIV64_IMM => x64asm!(out
            ; movsxd RTEMP, DWORD REL32_IMM
            ; push rax
            ; push rdx
            ; xor edx, edx
            ; mov rax, Rq(dst)
            ; div RTEMP
            ; mov Rq(dst), rax
            ; pop rdx
            ; pop rax
        ),
        ebpf::MOD64_IMM => x64asm!(out
            ; movsxd RTEMP, DWORD REL32_IMM
            ; push rax
            ; push rdx
            ; xor edx, edx
            ; mov rax, Rq(dst)
            ; div RTEMP
            ; mov Rq(dst), rdx
            ; pop rdx
            ; pop rax
        ),
        ebpf::LSH64_REG => x64asm!(out; shlx Rq(dst), Rq(dst), Rq(src)),
        ebpf::LSH32_REG => x64asm!(out; shlx Rd(dst), Rd(dst), Rd(src)),
        ebpf::RSH64_REG => x64asm!(out; shrx Rq(dst), Rq(dst), Rq(src)),
        ebpf::RSH32_REG => x64asm!(out; shrx Rd(dst), Rd(dst), Rd(src)),
        ebpf::ARSH64_REG => x64asm!(out; sarx Rq(dst), Rq(dst), Rq(src)),
        ebpf::ARSH32_REG => x64asm!(out; sarx Rd(dst), Rd(dst), Rd(src)),
        ebpf::LSH64_IMM => x64asm!(out
            ;; const { assert!(disposable_reg(RCX)) }
            ; mov cl, BYTE REL32_IMM
            ; shl Rq(dst), cl
        ),
        ebpf::LSH32_IMM => x64asm!(out
            ;; const { assert!(disposable_reg(RCX)) }
            ; mov cl, BYTE REL32_IMM
            ; shl Rd(dst), cl
        ),
        ebpf::RSH64_IMM => x64asm!(out
            ;; const { assert!(disposable_reg(RCX)) }
            ; mov cl, BYTE REL32_IMM
            ; shr Rq(dst), cl
        ),
        ebpf::RSH32_IMM => x64asm!(out
            ;; const { assert!(disposable_reg(RCX)) }
            ; mov cl, BYTE REL32_IMM
            ; shr Rd(dst), cl
        ),
        ebpf::ARSH64_IMM => x64asm!(out
            ;; const { assert!(disposable_reg(RCX)) }
            ; mov cl, BYTE REL32_IMM
            ; sar Rq(dst), cl
        ),
        ebpf::ARSH32_IMM => x64asm!(out
            ;; const { assert!(disposable_reg(RCX)) }
            ; mov cl, BYTE REL32_IMM
            ; sar Rd(dst), cl
        ),
        ebpf::BE => x64asm!(out
            ;; const { assert!(disposable_reg(RCX)) }
            ; xor ecx, ecx
            ; bswap Rq(dst)
            // `BE` has `BPF_X` set, yet the width is always the immediate.
            ; sub cl, BYTE REL32_IMM
            ; shr Rq(dst), cl
        ),
        ebpf::LE => x64asm!(out
            ; mov WTEMP, ALU_SRC32(src)
            ; bzhi Rq(dst), Rq(dst), RTEMP
        ),

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
            out.bpf_taken_branch();
        }

        // The supports read what they need from the instruction.
        ebpf::CALL_IMM => {
            load_next_insn_addr(out);
            out.meter_checked();
            match (out.version().static_syscalls(), src.0) {
                (false, _) => invoke_support(out, SupportingCode::get().v0_call_imm),
                (true, 1) => invoke_support(out, SupportingCode::get().call_imm),
                (true, 0) => invoke_support(out, SupportingCode::get().syscall),
                (true, _) => x64asm!(out; jmp ->sig_invalid_insn),
            }
        }
        ebpf::CALL_REG => {
            load_next_insn_addr(out);
            out.meter_checked();
            if out.version().callx_uses_dst_reg() {
                invoke_support(out, SupportingCode::get().callx[usize::from(dst.0)]);
            } else {
                invoke_support(out, SupportingCode::get().v0_callx);
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

        ebpf::LD_DW_IMM => {
            // The second half is another instruction with the more significant half of the
            // immediate.
            //
            // Counts as a single instruction, which moves the limit by one more slot. That's only
            // right once the instruction is within the budget, which means we gotta spend
            // additional code to check meter here.
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
        | ebpf::ST_DW_REG => {
            let size_log2 = match op & ebpf::BPF_SIZE_MASK {
                ebpf::BPF_B => 0,
                ebpf::BPF_H => 1,
                ebpf::BPF_W => 2,
                ebpf::BPF_DW => 3,
                _ => unreachable!(),
            };
            let (d, s) = (usize::from(dst.0), usize::from(src.0));
            let helper = match op & ebpf::BPF_CLS_MASK {
                ebpf::BPF_LDX => SupportingCode::get().load[size_log2][d][s],
                ebpf::BPF_ST => SupportingCode::get().store_imm[size_log2][d],
                ebpf::BPF_STX => SupportingCode::get().store_reg[size_log2][d][s],
                _ => unreachable!(),
            };
            load_next_insn_addr(out);
            invoke_support(out, helper);
        }

        0..=3
        | 6
        | 8..=11
        | 13..=14
        | 16..=19
        | 25..=27
        | 32..=35
        | 40..=43
        | 48..=51
        | 56..=59
        | 64..=67
        | 72..=75
        | 80..=83
        | 88..=91
        | 96
        | 104
        | 112
        | 120
        | 128..=131
        | 134
        | 136..=140
        | 142..=147
        | 150
        | 152..=155
        | 157..=158
        | 160..=163
        | 168..=171
        | 176..=179
        | 184..=187
        | 192..=195
        | 200..=203
        | 208..=211
        | 215..=219
        | 223..=246
        | 248..=255 => invalid_insn(out),
    }
}

/// Load the address of the BPF instruction following the current one into `temp`.
fn load_next_insn_addr<G: Generator + ?Sized>(out: &mut G) {
    x64asm!(out
        ; lea RTEMP, [ DWORD 0i32 + RINSN ]
        ;; out.template_reloc(TemplateRelocationKind::InsnOffset, 0, 4, 0, ABSOLUTE_DWORD)
    );
}

/// Call the support at `support_addr`, which finds `RINSN` above its return address.
fn invoke_support<G: Generator + ?Sized>(out: &mut G, support_addr: u32) {
    // Every other register holds something, so `RINSN` makes room for the target. The JIT code
    // need not be within reach of a 32-bit displacement from the supports.
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
/// This will discard the guest code stack, return the exit code in `al` and the
/// remaining budget in `RMETER`. `RTEMP` will contain the faulting instruction offset.
fn terminate<G: Generator + ?Sized>(out: &mut G, code: i8) {
    if code == SIG_EXCEEDED_MAX_INSTRUCTIONS {
        // If we did exceed the budget, the faulting instruction is actually the limit rather than
        // the address of whatever meter validation point we hit.
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
/// `temp` must contain the address of the next BPF instruction.
fn bpf_validate_meter<G: Generator + ?Sized>(out: &mut G) {
    out.meter_checked();
    x64asm!(out
        ; cmp RTEMP, RMETER
        ; ja ->sig_meter_exceeded
    );
}

/// Every template reserves this many relocations, so keep it at the maximum that any template
/// needs (`templates_fit_max_relocations` checks both directions).
/// The tracer's prelude takes another one.
pub(super) const MAX_RELOCATIONS: usize = if cfg!(feature = "tracer") { 4 } else { 3 };

pub(super) const MAX_JIT_TEMPLATE_SIZE: usize = if cfg!(feature = "tracer") { 64 } else { 48 };

/// Distance from the meter adjustment field of a taken branch to its jump field, see
/// `TemplateRelocationKind::TakenBranch`: the `jmp rel32` follows the `add r64, imm32`.
const TAKEN_BRANCH_METER_ADJUSTMENT: usize = 5;

#[derive(Clone, Copy, Debug)]
#[repr(u8)]
pub(super) enum TemplateRelocationKind {
    /// The JIT holds a pointer to the second instruction of the eBPF program in `insn`,
    /// whereas the templates default to addressing where `insn` is updated to point to right
    /// after the current instruction. This relocation adds the offset of the current instruction
    /// to the field.
    InsnOffset,
    /// When BPF instruction represents a branch, and the branch is taken, the control flow has to
    /// transfer to the machine code representing the target BPF instruction's code. Offset to this
    /// machine code is what this relocation must overwrite based on the BPF instruction being
    /// templated.
    ///
    /// The field `TAKEN_BRANCH_METER_ADJUSTMENT` bytes before it, which `bpf_taken_branch`
    /// always emits there, gets the offset (in bytes) from the instruction following the branch to
    /// the branch target.
    TakenBranch,
    /// For `jmp ->sig_meter_exceeded`.
    SigMeterExceeded,
    /// For `jmp ->sig_invalid_insn`.
    SigInvalidInsn,
}

/// A relocation that can only be resolved once the template is instantiated for a specific eBPF
/// instruction at a specific location: a 32-bit field in the template, which holds the addend, to
/// which the target of the relocation is added.
#[derive(Clone, Copy, Debug)]
pub(super) struct TemplateRelocation {
    /// Offset of the field within the template.
    pub(super) field: u8,
    pub(super) kind: TemplateRelocationKind,
}

impl TemplateRelocationKind {
    /// For a reference to the global label `name` in a template.
    pub(super) fn of_global(name: &str) -> Self {
        match name {
            "template_taken_branch" => Self::TakenBranch,
            "sig_meter_exceeded" => Self::SigMeterExceeded,
            "sig_invalid_insn" => Self::SigInvalidInsn,
            _ => panic!("global reference to an unknown symbol {}", name),
        }
    }
}

impl TemplateRelocation {
    /// For the unused entries, which `JitTemplates::emit` does not apply.
    pub(super) const UNUSED: Self = Self {
        field: 0,
        kind: TemplateRelocationKind::InsnOffset,
    };

    /// `patch` is a relocation reported by `dynasm` at the end of `code`, the template generated so
    /// far. Sets the field in `code` to the addend, which for relative relocations accounts for
    /// where the field is in the template, but not for where the template is in the output.
    pub(super) fn new(
        kind: TemplateRelocationKind,
        patch: PatchFields<Relocation>,
        code: &mut [u8],
    ) -> Self {
        let location = code.len();
        let relative = match kind {
            TemplateRelocationKind::TakenBranch
            | TemplateRelocationKind::SigMeterExceeded
            | TemplateRelocationKind::SigInvalidInsn => true,
            TemplateRelocationKind::InsnOffset => false,
        };
        assert!(
            match patch.relocation.kind() {
                RelocationKind::Relative => relative,
                RelocationKind::Absolute => !relative,
                RelocationKind::RelToAbs | RelocationKind::AbsToRel => false,
            },
            "unsupported template relocation"
        );
        assert_eq!(
            patch.relocation.size(),
            4,
            "unsupported template relocation"
        );
        let reference = if relative {
            location.checked_sub(usize::from(patch.ref_offset)).unwrap()
        } else {
            0
        };
        let field = location
            .checked_sub(usize::from(patch.field_offset))
            .unwrap();
        // The template ends no earlier than `location`, so the field is within it. `apply` relies
        // on this.
        assert!(
            field.checked_add(4).unwrap() <= location,
            "unsupported template relocation"
        );
        // `apply` also patches the meter adjustment ahead of the field.
        if let TemplateRelocationKind::TakenBranch = kind {
            assert!(
                field >= TAKEN_BRANCH_METER_ADJUSTMENT,
                "unsupported template relocation"
            );
        }
        let addend =
            i32::try_from(patch.target_offset.checked_sub(reference as isize).unwrap()).unwrap();
        code[field..field.wrapping_add(4)].copy_from_slice(&addend.to_le_bytes());
        Self {
            field: u8::try_from(field).unwrap(),
            kind,
        }
    }

    /// Patch the relocation into `out`, a copy of `template` instantiated as `at` describes.
    #[inline(always)]
    pub(super) fn apply<const SIZE: usize>(
        &self,
        template: &[u8; SIZE],
        out: &mut [u8; SIZE],
        at: &Instantiation,
    ) {
        // Computed in `i64`, to which all the inputs convert losslessly, and in which none of the
        // arithmetic below can overflow: the positions in the output are below `NOOP_DUE` (see
        // `analyze`), as are the `pc_section` entries, `pc * INSN_SIZE` is an offset into the text
        // section, and `off` and the addends are at most 32 bits.
        let target = match self.kind {
            TemplateRelocationKind::InsnOffset => {
                (at.pc as i64).wrapping_mul(ebpf::INSN_SIZE as i64)
            }
            TemplateRelocationKind::TakenBranch => {
                let adjustment = i64::from(at.off).wrapping_mul(ebpf::INSN_SIZE as i64);
                // At least `TAKEN_BRANCH_METER_ADJUSTMENT` (see `new`).
                let field = usize::from(self.field).wrapping_sub(TAKEN_BRANCH_METER_ADJUSTMENT);
                add_to_field(template, out, field, adjustment);
                // The verifier rejects invalid jump offsets, but doing this defensive thing is
                // faster anyway.
                let target = at
                    .pc
                    .checked_add_signed(isize::from(at.off).wrapping_add(1))
                    .and_then(|target_pc| at.pc_section.get(target_pc))
                    .copied()
                    .unwrap_or(JitTemplates::<SIZE>::INVALID_CALL_TARGET);
                i64::from(target & !PADDING_DUE).wrapping_sub(at.position as i64)
            }
            TemplateRelocationKind::SigMeterExceeded => {
                (at.sig_meter_exceeded as i64).wrapping_sub(at.position as i64)
            }
            TemplateRelocationKind::SigInvalidInsn => {
                (at.sig_invalid_insn as i64).wrapping_sub(at.position as i64)
            }
        };
        add_to_field(template, out, usize::from(self.field), target);
    }
}

/// Set the 32-bit field of a relocation at `field` in `out` to `value` plus what it holds in
/// `template`.
///
/// Reads `template` rather than `out`, which was just written with wider stores that a load of
/// the field couldn't be forwarded from.
///
/// `field` must be a field of a relocation of the template, or the meter adjustment of
/// `TemplateRelocationKind::TakenBranch`.
#[inline(always)]
fn add_to_field<const SIZE: usize>(
    template: &[u8; SIZE],
    out: &mut [u8; SIZE],
    field: usize,
    value: i64,
) {
    debug_assert!(field.wrapping_add(4) <= SIZE);
    // SAFETY:
    //
    // Contract from `<*const u8>::add`: The offset in bytes, `count * size_of::<T>()`, computed on
    // mathematical integers (without "wrapping around"), must fit in an `isize`.
    //
    // Contract from `<*const u8>::add`: If the computed offset is non-zero, then `self` must be
    // derived from a pointer to some allocation, and the entire memory range between `self` and the
    // result must be in bounds of that allocation. In particular, this range must not "wrap around"
    // the edge of the address space.
    //
    // Contract from `<*const i32>::read_unaligned`: See `ptr::read_unaligned` for safety concerns
    // and examples.
    //
    // Contract from `ptr::read_unaligned`: `src` must be valid for reads.
    //
    // Contract from `ptr::read_unaligned`: `src` must point to a properly initialized value of type
    // `T`.
    //
    // Contract from `<*mut u8>::add`: The offset in bytes, `count * size_of::<T>()`, computed on
    // mathematical integers (without "wrapping around"), must fit in an `isize`.
    //
    // Contract from `<*mut u8>::add`: If the computed offset is non-zero, then `self` must be
    // derived from a pointer to some allocation, and the entire memory range between `self` and the
    // result must be in bounds of that allocation. In particular, this range must not "wrap around"
    // the edge of the address space.
    //
    // Contract from `<*mut i32>::write_unaligned`: See `ptr::write_unaligned` for safety concerns
    // and examples.
    //
    // Contract from `ptr::write_unaligned`: `dst` must be valid for writes.
    //
    // Evidence: `TemplateRelocation::new` asserts that a field ends within its template, so `field
    // + 4` is at most the length of the template, and that the meter adjustment of a taken branch,
    // `TAKEN_BRANCH_METER_ADJUSTMENT` bytes before its field, is within it too. That is at
    // most `SIZE`, so `field` is an offset within the arrays `template` and `out`, which fits an
    // `isize`, and the 4 bytes at it are within either array. They are initialized bytes, and any 4
    // of them are a valid `i32`. `out` is borrowed mutably, so writing to it is allowed.
    unsafe {
        let addend = template.as_ptr().add(field).cast::<i32>().read_unaligned();
        debug_assert!(
            i32::try_from(i64::from(addend).wrapping_add(value)).is_ok(),
            "impossible relocation"
        );
        let field = out.as_mut_ptr().add(field).cast::<i32>();
        field.write_unaligned(addend.wrapping_add(value as i32));
    }
}

/// The interpreter steps are 128 bytes.
pub(super) const INTERPRETER_STEP_SIZE_LOG2: u8 = 7;

/// What the space after the code of an interpreter step is filled with: `int3`.
pub(super) const TRAP_FILL: u8 = 0xcc;

/// The encoding of an absolute 32-bit relocation, for `Generator::template_reloc`.
const ABSOLUTE_DWORD: u8 = 0xc2;

/// The address of the code that the global label `name` of an interpreter step refers to.
///
/// It is shared by the steps, so it is in the supports, which like the interpreter are in the
/// first 2 GiB, so within reach.
pub(super) fn interpreter_global(name: &str) -> usize {
    let supports = SupportingCode::get();
    let target = match name {
        "sig_meter_exceeded" => supports.meter_exceeded,
        "sig_invalid_insn" => supports.invalid_insn,
        _ => panic!("global reference to an unknown symbol {}", name),
    };
    target as usize
}

/// Generate the `AuxTemplate` `template`.
pub(super) fn aux_template<G: Generator + ?Sized>(out: &mut G, template: AuxTemplate) {
    match template {
        AuxTemplate::ExecutionOverrun => {
            load_next_insn_addr(out);
            // Running out of budget takes precedence, as in `Interpreter::step`.
            bpf_validate_meter(out);
            terminate(out, SIG_EXECUTION_OVERRUN);
        }
        AuxTemplate::InvalidCallTarget => {
            // The code paths that might end up here are expected to update `next_insn`.
            x64asm!(out; mov RTEMP, rbp => Frame[BYTE -1].next_insn);
            #[cfg(feature = "tracer")]
            invoke_support(out, SupportingCode::get().trace);
            // Continues into `InvalidInsn`.
        }
        AuxTemplate::SigInvalidInsn => {
            bpf_validate_meter(out);
            terminate(out, SIG_INVALID_INSN);
        }
        AuxTemplate::SigMeterExceeded => terminate(out, SIG_EXCEEDED_MAX_INSTRUCTIONS),
        AuxTemplate::Noop => x64asm!(out; nop),
        AuxTemplate::MeterCheckpoint => {
            load_next_insn_addr(out);
            bpf_validate_meter(out);
        }
    }
}

/// `Generator::bpf_taken_branch` of the JIT templates.
pub(super) fn jit_taken_branch<G: Generator + ?Sized>(out: &mut G) {
    // The `TakenBranch` relocation of the `jmp` also patches the adjustment.
    x64asm!(out; add RMETER, DWORD 0);
    let adjustment = out.offset();
    x64asm!(out; jmp ->template_taken_branch);
    assert_eq!(
        out.offset().wrapping_sub(adjustment),
        TAKEN_BRANCH_METER_ADJUSTMENT,
        "the adjustment must precede the jump field"
    );
}

/// `Generator::bpf_taken_branch` of the interpreter steps, which `interpreter_dispatch` follows.
pub(super) fn interpreter_taken_branch<G: Generator + ?Sized>(out: &mut G) {
    x64asm!(out
        ; movsx RTEMP, WORD REL32_OFF
        ; lea RMETER, [ RMETER + RTEMP*8 ]
        ; lea RINSN, [ RINSN + RTEMP*8 ]
    );
}

/// Generate the end of an interpreter step, which dispatches to the step of the next instruction.
pub(super) fn interpreter_dispatch(out: &mut InterpreterGenerator) {
    let base_addr = i32::try_from(out.base() as usize).expect("interpreter in first 2GB");
    // `insn` points at the last 8 bytes of the instruction just executed.
    let size = i8::try_from(ebpf::opcode_size(out.opcode().op())).unwrap();
    let to_last = size.checked_sub(8).unwrap();
    let next_insn = if size == 8 {
        RINSN
    } else {
        x64asm!(out; lea RTEMP, [ BYTE to_last + RINSN ]);
        RTEMP
    };
    // Before dispatching the next instruction, check what the JIT does with the meter
    // checkpoints and the `execution_overrun` template, in the order of `Interpreter::step`.
    // `meter` and the limit are both the end of the last instruction that may be executed.
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

/// The state of an execution. `SupportingCode::entry_point` copies it right below its frame
/// pointer, where the generated code finds it as `rbp => Frame[BYTE -1].field`.
#[repr(C, align(16))]
struct Frame {
    /// The `EbpfVm` being executed.
    vm: *mut u8,
    /// Where `terminate` jumps to. Set up by `SupportingCode::entry_point`.
    exit: *const u8,
    /// The address of the instruction following the target of the call (or the call just executed)
    /// in anticipation of possible invalid instruction exception.
    next_insn: *const u8,
    text_section: *const u8,
    /// Length of `text_section` in bytes.
    text_section_len: u64,
    /// The end of `text_section`.
    text_section_limit: *const u8,
    /// Translates host addresses within `text_section` to VM addresses.
    text_section_host_to_vm: u64,
    /// For the JIT output: offset in `jit_text_section` of the machine code for each instruction
    /// of `text_section`. Null for the interpreter.
    jit_pc_section: *const u32,
    /// Code being executed. For JIT the generated machine code, for interpreter the steps base.
    code: *const u8,
    /// See `supporting_code::call_dispatcher`.
    call_dispatcher: *const u8,
    /// The `FunctionRegistry<usize>` of the executable, for the dispatcher of SBPFv0.
    function_registry: *const u8,
    /// How many more internal calls there can be before `CallDepthExceeded`.
    calls_remaining: u64,
    /// How much a call moves the frame pointer by.
    stack_frame_bump: u64,
}

/// Run `executable` starting at `vm.registers[11]`, with `vm.previous_instruction_meter` as the
/// budget.
///
/// `jit` is the `pc_section` and the machine code (in executable memory) of the JIT output for the
/// `executable`, or `None` to interpret it.
pub(super) fn enter<C: ContextObject>(
    executable: &Executable<C>,
    jit: Option<(&[u32], *const u8)>,
    vm: &mut EbpfVm<C>,
) {
    let version = executable.get_sbpf_version();
    let (bpf_vm_addr, bpf) = executable.get_text_bytes();
    let pc = vm.registers[11] as usize;
    let (start_addr, insn, jit_pc_section, code) = match jit {
        Some((pc_section, text_section)) => (
            (text_section as usize).wrapping_add(pc_section[pc] as usize),
            bpf.as_ptr().wrapping_add(ebpf::INSN_SIZE),
            pc_section.as_ptr(),
            text_section,
        ),
        None => {
            // `pc` is bounds checked by the indexing below.
            let starting_insn = bpf.as_chunks::<{ ebpf::INSN_SIZE }>().0[pc];
            let opcode = TemplateOpcode::of(u64::from_le_bytes(starting_insn));
            (
                generate::interpreter_step(version, opcode) as usize,
                bpf.as_ptr()
                    .wrapping_add(pc.wrapping_add(1).wrapping_mul(ebpf::INSN_SIZE)),
                std::ptr::null(),
                generate::interpreter(version).buffer.cast_const(),
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
    // the generated code calls are `extern "sysv64"`, which does not unwind, so a panic in them
    // aborts. The memory the code accesses is reachable from the pointers passed in, as for an FFI
    // function: `frame`, which outlives the call, and through it the `EbpfVm`, the executable's
    // text and function registry, and the code at `start_addr` (the JIT output or the interpreter
    // of the same `version`, which outlives the call too). The stack is used below the stack
    // pointer with pushes and calls, a few words per internal call, of which there are at most
    // `max_call_depth`, and as each push touches the word below the last, an overflow hits the
    // guard page. Nothing the code emits sets the direction flag, uses x87 or ends with a prefix.
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

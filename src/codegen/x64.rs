use dynasmrt::relocations::SimpleRelocation;
use dynasmrt::DynamicLabel;

use super::*;
use crate::vm::RuntimeEnvironmentSlot;
use std::convert::TryFrom;
use std::sync::LazyLock;

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
    RBX, // r10 = rbx // FIXME: this should be a special case read-only register. We should take
         // care to generate instructions accordingly.
];

/// `insn` with its BPF registers mapped to the machine ones, or `u8::MAX` for the register
/// numbers not naming a BPF register.
fn with_machine_regs(insn: TemplateInsn) -> TemplateInsn {
    let reg = |bpf_reg: u8| {
        GPREG_MAP
            .get(usize::from(bpf_reg))
            .copied()
            .unwrap_or(u8::MAX)
    };
    TemplateInsn {
        op: insn.op,
        dst: reg(insn.dst),
        src: reg(insn.src),
    }
}

/// Is the value in the provided register disposable/temporary?
pub const fn disposable_reg(reg: u8) -> bool {
    reg == RCX
}

macro_rules! x64asm {
    ($output: expr; $($tts:tt)*) => { x64asm!(@munch {$output; [] []} ; $($tts)*) };
    (@munch {$output:expr; [$($acc:tt)*] [$($curr:tt)*]}) => {
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
            ; .alias BTEMP, cl
            ; .alias RMETER, rdx
            $($acc)* $($curr)*
        )
    };

    // replace ALU_SRC() operand with either a source register for ALU instructions using source
    // register operand, or an immediate fetch for `_IMM` ALU instructions.
    (@munch {$output:expr; [$($acc:tt)*] [$($curr:tt)*]} ALU_SRC8 $($rest:tt)*) => {
        x64asm!(@munch {$output; [ $($acc)* ] [ ; if ($output.insn().op & ebpf::BPF_X) == ebpf::BPF_X {
            x64asm!(@munch {$output; [;] [$($curr)*]} Rb($output.insn().src))
          } else {
            x64asm!(@munch {$output; [;] [$($curr)*]} BYTE REL32_IMM)
          }
        ]} $($rest)*)
    };
    (@munch {$output:expr; [$($acc:tt)*] [$($curr:tt)*]} ALU_SRC32 $($rest:tt)*) => {
        x64asm!(@munch {$output; [ $($acc)* ] [ ; if ($output.insn().op & ebpf::BPF_X) == ebpf::BPF_X {
            x64asm!(@munch {$output; [;] [$($curr)*]} Rd($output.insn().src))
          } else {
            x64asm!(@munch {$output; [;] [$($curr)*]} DWORD REL32_IMM)
          }
        ]} $($rest)*)
    };

    (@munch {$output:expr; [$($acc:tt)*] [$($curr:tt)*]} REL32_IMM $($rest:tt)*) => {
        x64asm!(@munch {$output; [ $($acc)* ] [
            $($curr)* [ DWORD -4i32 + RINSN ] ;; $output.template_reloc(TemplateRelocationKind::InsnOffset, -4, 4, 0)
        ]} $($rest)*)
    };

    (@munch {$output:expr; [$($acc:tt)*] [$($curr:tt)*]} REL32_OFF $($rest:tt)*) => {
        x64asm!(@munch {$output; [ $($acc)* ] [
            $($curr)* [ DWORD -6i32 + RINSN ] ;; $output.template_reloc(TemplateRelocationKind::InsnOffset, -6, 4, 0)
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

mod supporting_code;
use supporting_code::SupportingCode;

trait X64Generator {
    type DynamicLabel: Copy;

    fn extend(&mut self, buffer: &[u8]);
    fn offset(&self) -> usize;
    fn push(&mut self, byte: u8);
    fn push_i8(&mut self, value: i8);
    fn push_i32(&mut self, value: i32);
    fn push_i64(&mut self, value: i64) {
        self.extend(&value.to_le_bytes());
    }
    fn align(&mut self, alignment: usize, with: u8);
    fn global_reloc(
        &mut self,
        name: &'static str,
        target_offset: isize,
        field_offset: u8,
        ref_offset: u8,
        kind: u8,
    );
    fn dynamic_reloc(
        &mut self,
        id: Self::DynamicLabel,
        target_offset: isize,
        field_offset: u8,
        ref_offset: u8,
        kind: u8,
    );
    /// Record a template relocation for bytes immediately preceding the current offset.
    ///
    /// The field is overwritten based on BPF instruction data as the templates are assembled. This
    /// is unlike the other types of relocations which have to be resolved or resolvable when the
    /// template is finalized.
    fn template_reloc(
        &mut self,
        kind: TemplateRelocationKind,
        target_offset: isize,
        field_offset: u8,
        ref_offset: u8,
    );
    fn new_dynamic_label(&mut self) -> Self::DynamicLabel;
    fn dynamic_label(&mut self, id: Self::DynamicLabel);

    /// The instruction being generated, with the physical registers (see `physical_regs`.)
    fn insn(&self) -> TemplateInsn;
    fn supports(&self) -> &SupportingCode;

    // Generate code to handle branch taken case.
    fn bpf_taken_branch(&mut self);
}

/// Produce a template for a single (currently processed) instruction.
fn bpf_insn_template<G: X64Generator + ?Sized>(out: &mut G) {
    let TemplateInsn { op, dst, src } = out.insn();
    let is_alu64 = (op & ebpf::BPF_CLS_MASK) == ebpf::BPF_ALU64_STORE;

    match op {
        ebpf::NEG32 => x64asm!(out; neg Rd(dst)),
        ebpf::NEG64 => x64asm!(out; neg Rq(dst)),
        #[rustfmt::skip]
        ebpf::OR32_IMM |
        ebpf::OR32_REG => x64asm!(out; or Rd(dst), ALU_SRC32),
        ebpf::OR64_IMM => x64asm!(out
            ; movsxd RTEMP, DWORD REL32_IMM
            ; or Rq(dst), RTEMP
        ),
        #[rustfmt::skip]
        ebpf::OR64_REG => if dst != src { x64asm!(out
            ; or Rq(dst), Rq(src)
        )},
        ebpf::HOR64_IMM => x64asm!(out
            ; mov WTEMP, ALU_SRC32
            ; shl RTEMP, 32
            ; or Rq(dst), RTEMP
        ),
        #[rustfmt::skip]
        ebpf::AND32_IMM |
        ebpf::AND32_REG => x64asm!(out; and Rd(dst), ALU_SRC32),
        #[rustfmt::skip]
        ebpf::AND64_IMM => x64asm!(out
            ; movsxd RTEMP, DWORD REL32_IMM
            ; and Rq(dst), RTEMP
        ),
        #[rustfmt::skip]
        ebpf::AND64_REG => if dst != src { x64asm!(out
            ; and Rq(dst), Rq(src)
        )},
        #[rustfmt::skip]
        ebpf::XOR32_IMM |
        ebpf::XOR32_REG => x64asm!(out; xor Rd(dst), ALU_SRC32),
        ebpf::XOR64_IMM => x64asm!(out
            ; movsxd RTEMP, DWORD REL32_IMM
            ; xor Rq(dst), RTEMP
        ),
        ebpf::XOR64_REG => x64asm!(out; xor Rq(dst), Rq(src)),
        ebpf::MOV32_IMM => x64asm!(out; mov Rd(dst), ALU_SRC32),
        ebpf::MOV64_IMM => x64asm!(out; movsxd Rq(dst), ALU_SRC32),
        ebpf::MOV32_REG => x64asm!(out; mov Rd(dst), Rd(src)),
        #[rustfmt::skip]
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
            ; add Rd(dst), ALU_SRC32
            ; movsxd Rq(dst), Rd(dst)
        ),
        ebpf::SUB32_IMM | ebpf::SUB32_REG => x64asm!(out
            ; sub Rd(dst), ALU_SRC32
            ; movsxd Rq(dst), Rd(dst)
        ),
        ebpf::MUL32_IMM | ebpf::MUL32_REG => x64asm!(out
            ; imul Rd(dst), ALU_SRC32
            ; movsxd Rq(dst), Rd(dst)
        ),
        #[rustfmt::skip]
        ebpf::DIV32_IMM |
        ebpf::DIV32_REG |
        ebpf::MOD32_IMM |
        ebpf::MOD32_REG |
        ebpf::DIV64_IMM |
        ebpf::DIV64_REG |
        ebpf::MOD64_IMM |
        ebpf::MOD64_REG => {
            let is_div = (op & ebpf::BPF_ALU_OP_MASK) == ebpf::BPF_DIV;
            let is_reg = (op & ebpf::BPF_X) == ebpf::BPF_X;
            if let Some(helper) = out.supports().divide(is_div, is_alu64, is_reg, dst, src) {
                load_next_insn(out);
                invoke_support(out, helper);
            } else {
                load_next_insn(out);
                terminate(out, SIG_INVALID_INSN);
            }
        }
        ebpf::LSH64_IMM | ebpf::LSH64_REG => x64asm!(out
            // if failing, you can switch to shlx/shrx/sarx
            ;; const { assert!(disposable_reg(RCX)) }
            ; mov cl, ALU_SRC8
            ; shl Rq(dst), cl
        ),
        ebpf::LSH32_IMM | ebpf::LSH32_REG => x64asm!(out
            ;; const { assert!(disposable_reg(RCX)) }
            ; mov cl, ALU_SRC8
            ; shl Rd(dst), cl
        ),
        ebpf::RSH64_IMM | ebpf::RSH64_REG => x64asm!(out
            ;; const { assert!(disposable_reg(RCX)) }
            ; mov cl, ALU_SRC8
            ; shr Rq(dst), cl
        ),
        ebpf::RSH32_IMM | ebpf::RSH32_REG => x64asm!(out
            ;; const { assert!(disposable_reg(RCX)) }
            ; mov cl, ALU_SRC8
            ; shr Rd(dst), cl
        ),
        ebpf::ARSH64_IMM | ebpf::ARSH64_REG => x64asm!(out
            ;; const { assert!(disposable_reg(RCX)) }
            ; mov cl, ALU_SRC8
            ; sar Rq(dst), cl
        ),
        ebpf::ARSH32_IMM | ebpf::ARSH32_REG => x64asm!(out
            ;; const { assert!(disposable_reg(RCX)) }
            ; mov cl, ALU_SRC8
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
            ; mov WTEMP, ALU_SRC32
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
        | ebpf::JSLE32_IMM
        | ebpf::JLE64_IMM
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
        | ebpf::JSLE64_REG => {
            load_next_insn(out);
            bpf_validate_meter(out);
            let is_64 = (op & ebpf::BPF_CLS_MASK) == ebpf::BPF_JMP64;
            let is_imm = (op & ebpf::BPF_X) != ebpf::BPF_X;
            let is_jset = (op & ebpf::BPF_ALU_OP_MASK) == ebpf::BPF_JSET;
            match (is_64, is_imm, is_jset) {
                (true, true, false) => x64asm!(out
                    ; movsxd RTEMP, DWORD REL32_IMM
                    ; cmp Rq(dst), RTEMP
                ),
                (true, true, true) => x64asm!(out
                    ; movsxd RTEMP, DWORD REL32_IMM
                    ; test Rq(dst), RTEMP
                ),
                (true, false, false) => x64asm!(out; cmp Rq(dst), Rq(src)),
                (true, false, true) => x64asm!(out; test Rq(dst), Rq(src)),
                (false, true, false) => x64asm!(out; cmp Rd(dst), DWORD REL32_IMM),
                (false, true, true) => x64asm!(out; test Rd(dst), DWORD REL32_IMM),
                (false, false, false) => x64asm!(out; cmp Rd(dst), Rd(src)),
                (false, false, true) => x64asm!(out; test Rd(dst), Rd(src)),
            }
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
                _ => {
                    load_next_insn(out);
                    terminate(out, SIG_INVALID_INSN)
                }
            }
            out.bpf_taken_branch();
            out.dynamic_label(fallthrough);
        }
        ebpf::JA => {
            load_next_insn(out);
            bpf_validate_meter(out);
            out.bpf_taken_branch();
        }

        ebpf::CALL_IMM => {
            load_next_insn(out);
            if src == GPREG_MAP[1] {
                let call_internal = out.supports().call_internal;
                x64asm!(out
                    ; push RTEMP
                    ; movsxd RTEMP, DWORD REL32_IMM
                    ; lea RTEMP, [ DWORD 0i32 + RINSN + RTEMP * 8 ]
                    ;; out.template_reloc(TemplateRelocationKind::InsnOffset, 0, 4, 0)
                    ;; invoke_support(out, call_internal)
                    ; pop RTEMP
                );
            } else if src == GPREG_MAP[0] {
                invoke_support(out, out.supports().syscall);
            } else {
                terminate(out, SIG_INVALID_INSN)
            }
        }
        ebpf::CALL_REG => {
            load_next_insn(out);
            if dst == u8::MAX {
                terminate(out, SIG_INVALID_INSN)
            } else {
                let call_internal = out.supports().call_internal;
                x64asm!(out
                    ; push RTEMP
                    ; mov RTEMP, Rq(dst)
                    ; gs sub RTEMP, [ RuntimeEnvironmentSlot::TextSectionHostToVm as i32 ]
                    ;; invoke_support(out, call_internal)
                    ; pop RTEMP
                );
            }
        }
        ebpf::EXIT => {
            load_next_insn(out);
            bpf_validate_meter(out);
            x64asm!(out
                ; sub RMETER, RTEMP
                ; xor WTEMP, WTEMP
                ; ret
            );
        }

        // The second half is another instruction with the more significant half of the immediate.
        ebpf::LD_DW_IMM => x64asm!(out
            ; mov Rd(dst), DWORD REL32_IMM
            ; mov WTEMP, DWORD [ DWORD 4i32 + RINSN ]
            ;; out.template_reloc(TemplateRelocationKind::InsnOffset, 4, 4, 0)
            ; shl RTEMP, 32
            ; or Rq(dst), RTEMP
            // Counts as a single instruction.
            ; add RMETER, ebpf::INSN_SIZE as i32
        ),

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
            let kind = match op & ebpf::BPF_CLS_MASK {
                ebpf::BPF_LDX => MemoryAccessKind::Load,
                ebpf::BPF_ST => MemoryAccessKind::StoreImm,
                ebpf::BPF_STX => MemoryAccessKind::StoreReg,
                _ => unreachable!(),
            };
            let size_log2 = match op & ebpf::BPF_SIZE_MASK {
                ebpf::BPF_B => 0,
                ebpf::BPF_H => 1,
                ebpf::BPF_W => 2,
                ebpf::BPF_DW => 3,
                _ => unreachable!(),
            };
            let helper = out.supports().memory_access[kind as usize][size_log2];
            let uses_src = kind != MemoryAccessKind::StoreImm;
            load_next_insn(out);
            if dst == u8::MAX || (uses_src && src == u8::MAX) {
                terminate(out, SIG_INVALID_INSN);
            } else {
                match kind {
                    MemoryAccessKind::Load => x64asm!(out
                        ; push Rq(src)
                        ;; invoke_support(out, helper)
                        ; pop Rq(dst)
                    ),
                    MemoryAccessKind::StoreImm => x64asm!(out
                        ; push Rq(dst)
                        ;; invoke_support(out, helper)
                        ; pop RTEMP
                    ),
                    MemoryAccessKind::StoreReg => x64asm!(out
                        ; push Rq(dst)
                        ; push Rq(src)
                        ;; invoke_support(out, helper)
                        ; add rsp, 16
                    ),
                }
            }
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
        | 223..=229
        | 230..=237
        | 238..=246
        | 248..=255 => {
            load_next_insn(out);
            terminate(out, SIG_INVALID_INSN)
        }
    }
}

/// Load the address of the BPF instruction following the current one into `temp`.
fn load_next_insn<G: X64Generator + ?Sized>(out: &mut G) {
    x64asm!(out
        ; lea RTEMP, [ DWORD 0i32 + RINSN ]
        ;; out.template_reloc(TemplateRelocationKind::InsnOffset, 0, 4, 0)
    );
}

fn invoke_support<G: X64Generator + ?Sized>(out: &mut G, support_addr: *const u8) {
    let support_dword = u32::try_from(support_addr as usize).unwrap() as i32;
    x64asm!(out
        ; push DWORD support_dword
        ; call QWORD [rsp]
        ; add rsp, BYTE 8
    );
}

/// Terminate execution with the specified code.
///
/// Unless `code` is `SIG_EXCEEDED_MAX_INSTRUCTIONS`, `temp` must contain the address of the
/// BPF instruction following the one terminating the execution.
///
/// This will discard the guest code stack and return the exit code in `temp` and the
/// remaining instruction budget in `meter`.
fn terminate<G: X64Generator + ?Sized>(out: &mut G, code: i8) {
    if code != SIG_EXCEEDED_MAX_INSTRUCTIONS {
        // Update `meter` only when we don't know that the remainder is already 0. Callers can
        // check the return code and determine if they need to interpret the remainder without
        // cluttering every point in generated JIT code.
        x64asm!(out; sub RMETER, RTEMP);
    }
    x64asm!(out
        ; mov BTEMP, code
        ; jmp QWORD [rbp - 8]
    );
}

/// Terminate the execution if the instruction budget has been exceeded.
///
/// `temp` must contain the address of the next BPF instruction.
fn bpf_validate_meter<G: X64Generator + ?Sized>(out: &mut G) {
    let within_budget = out.new_dynamic_label();
    x64asm!(out
        ; cmp RTEMP, RMETER
        ; jbe BYTE =>within_budget
        ;; terminate(out, SIG_EXCEEDED_MAX_INSTRUCTIONS)
        ; =>within_budget
    );
}

const MAX_JIT_TEMPLATE_SIZE: usize = 48;

struct JITGenerator {
    template: super::Template<MAX_JIT_TEMPLATE_SIZE, TemplateRelocation<SimpleRelocation>>,
    /// With BPF register numbers.
    insn: TemplateInsn,
    /// Temporary relocations within the code that will be resolved before the template is
    /// finalized.
    ///
    /// Template can have further relocations after finalization, however those relocations may only
    /// be specific to the eBPF instruction being instantiated.
    relocs: LabelRelocs<SimpleRelocation>,
    supports: &'static SupportingCode,
}

impl JITGenerator {
    pub fn new() -> Self {
        Self {
            template: super::Template::new(),
            insn: TemplateInsn {
                op: 0,
                dst: 0,
                src: 0,
            },
            relocs: LabelRelocs::new(),
            supports: &INTERPRETER_AND_SUPPORTS.1,
        }
    }

    /// Resolve all the relocations that can be resolved without knowing the specific eBPF
    /// instruction and return the template. The generator is reset to generate the next template.
    fn finalize(
        &mut self,
    ) -> Template<MAX_JIT_TEMPLATE_SIZE, TemplateRelocation<SimpleRelocation>> {
        let mut template = std::mem::replace(&mut self.template, Template::new());
        self.relocs.resolve(template.buffer_mut(), None);
        template
    }
}

impl X64Generator for JITGenerator {
    type DynamicLabel = DynamicLabel;

    #[track_caller]
    fn extend(&mut self, buffer: &[u8]) {
        self.template.extend(buffer);
    }

    fn offset(&self) -> usize {
        self.template.offset()
    }

    fn push(&mut self, byte: u8) {
        self.template.push(byte)
    }

    fn push_i32(&mut self, value: i32) {
        self.template.push_i32(value);
    }

    fn push_i8(&mut self, value: i8) {
        self.template.push_i8(value);
    }

    fn align(&mut self, _alignment: usize, _with: u8) {
        // Ignore alignment requests; we're generating templates.
    }

    fn global_reloc(
        &mut self,
        name: &'static str,
        target_offset: isize,
        field_offset: u8,
        ref_offset: u8,
        kind: u8,
    ) {
        let patch = PatchFields::new(target_offset, field_offset, ref_offset, kind);
        let kind = match name {
            "template_taken_branch" => TemplateRelocationKind::TakenBranch,
            _ => panic!("global reference to an unknown symbol {}", name),
        };
        self.template.add_relocation(TemplateRelocation {
            location: self.offset(),
            patch,
            kind,
        });
    }

    fn template_reloc(
        &mut self,
        kind: TemplateRelocationKind,
        target_offset: isize,
        field_offset: u8,
        ref_offset: u8,
    ) {
        // kind = Absolute DWord
        let patch = PatchFields::new(target_offset, field_offset, ref_offset, 0xC2);
        self.template.add_relocation(TemplateRelocation {
            location: self.offset(),
            patch,
            kind,
        });
    }

    fn dynamic_reloc(
        &mut self,
        id: DynamicLabel,
        target_offset: isize,
        field_offset: u8,
        ref_offset: u8,
        kind: u8,
    ) {
        let patch = PatchFields::new(target_offset, field_offset, ref_offset, kind);
        self.relocs.dynamic_reloc(self.offset(), id, patch);
    }

    fn new_dynamic_label(&mut self) -> DynamicLabel {
        self.relocs.new_dynamic_label()
    }

    fn dynamic_label(&mut self, id: DynamicLabel) {
        self.relocs.dynamic_label(id, self.offset());
    }

    fn insn(&self) -> TemplateInsn {
        with_machine_regs(self.insn)
    }

    fn supports(&self) -> &SupportingCode {
        self.supports
    }

    fn bpf_taken_branch(&mut self) {
        x64asm!(self
            ; add RMETER, DWORD 0
            ;; self.template_reloc(TemplateRelocationKind::TakenBranchMeterAdjustment, 0, 4, 0)
            ; jmp ->template_taken_branch
        );
    }
}

// TODO: when dynasm supports const codegen, we can make these be generated at compile time into an
// array.
/// JIT templates for SBPFv3.
pub static JIT_TEMPLATES: LazyLock<JitTemplates<MAX_JIT_TEMPLATE_SIZE, SimpleRelocation>> =
    LazyLock::new(|| {
        let mut insns = Vec::with_capacity(0x10000);
        let mut generator = JITGenerator::new();
        for insn in template_insns() {
            generator.insn = insn;
            bpf_insn_template(&mut generator);
            insns.push(generator.finalize());
        }
        load_next_insn(&mut generator);
        terminate(&mut generator, SIG_EXECUTION_OVERRUN);
        let execution_overrun = generator.finalize();
        terminate(&mut generator, SIG_INVALID_INSN);
        let invalid_jump_target = generator.finalize();
        JitTemplates {
            insns,
            execution_overrun,
            invalid_jump_target,
        }
    });

/// The interpreter step for the instruction with the lower 16 bits `insn`.
pub(super) fn interpreter_step(insn: u16) -> *const u8 {
    let offset = usize::from(insn) << InterpreterGenerator::STEP_SIZE_LOG2;
    unsafe { INTERPRETER_AND_SUPPORTS.0.buffer.add(offset) }
}

pub struct Interpreter {
    buffer: *mut u8,
}

unsafe impl Send for Interpreter {}
unsafe impl Sync for Interpreter {}

impl Drop for Interpreter {
    fn drop(&mut self) {
        unsafe {
            libc::munmap(self.buffer.cast(), InterpreterGenerator::STEPS_SIZE);
        }
    }
}

/// Generate an interpreter...
struct InterpreterGenerator {
    buffer: *mut u8,
    relocs: LabelRelocs<SimpleRelocation>,
    supports: SupportingCode,
    offset: usize,
    /// With BPF register numbers.
    insn: TemplateInsn,
    /// Is the code generated for this instruction terminal?
    ///
    /// No further instructions other than the epilogue expected to appear after this point.
    terminal: bool,
}

impl InterpreterGenerator {
    const STEP_SIZE_LOG2: u8 = 7; // 128 bytes
    const STEP_TABLE_SIZE: usize = 0x1_0000 * (1 << Self::STEP_SIZE_LOG2);
    const STEPS_SIZE: usize = Self::STEP_TABLE_SIZE + SupportingCode::LEN;

    pub fn new() -> Self {
        unsafe {
            #[cfg(feature = "codegen_debug")]
            let file = {
                let file = std::fs::OpenOptions::new()
                    .read(true)
                    .write(true)
                    .create(true)
                    .truncate(true)
                    .open("interpreter.bin")
                    .unwrap();
                file.set_len(Self::STEPS_SIZE as u64).unwrap();
                file
            };
            #[cfg(feature = "codegen_debug")]
            let (flags, fd) = (libc::MAP_SHARED, std::os::fd::AsRawFd::as_raw_fd(&file));
            #[cfg(not(feature = "codegen_debug"))]
            let (flags, fd) = (libc::MAP_PRIVATE | libc::MAP_ANONYMOUS, -1);

            let buffer = libc::mmap(
                std::ptr::null_mut(),
                Self::STEPS_SIZE,
                libc::PROT_READ | libc::PROT_WRITE,
                flags | libc::MAP_32BIT,
                fd,
                0,
            );
            if buffer == libc::MAP_FAILED {
                panic!("libc::mmap failed to allocate executable memory for the interpreter");
            }

            let mut this = Self {
                buffer: buffer.cast(),
                relocs: LabelRelocs::new(),
                offset: 0,
                insn: TemplateInsn {
                    op: 0,
                    dst: 0,
                    src: 0,
                },
                terminal: false,
                supports: SupportingCode {
                    call_internal: std::ptr::null(),
                    syscall: std::ptr::null(),
                    memory_access: [[std::ptr::null(); 4]; 3],
                    entry_point: std::ptr::null(),
                    divide: Vec::new(),
                },
            };
            this.offset = Self::STEP_TABLE_SIZE;
            let supporting_code = SupportingCode::generate_into(&mut this);
            this.offset = 0;
            this.supports = supporting_code;
            this
        }
    }
}

impl X64Generator for InterpreterGenerator {
    type DynamicLabel = DynamicLabel;

    fn extend(&mut self, buffer: &[u8]) {
        assert!(!self.terminal);
        assert!(self.offset.saturating_add(buffer.len()) < InterpreterGenerator::STEPS_SIZE);
        // `SupportingCode` lives past the dispatch table and isn't split into steps.
        if self.offset < Self::STEP_TABLE_SIZE {
            let step_capacity = 1 << Self::STEP_SIZE_LOG2;
            let remaining_capacity = step_capacity - self.offset % step_capacity;
            assert!(buffer.len() <= remaining_capacity, "step is too long!");
        }
        unsafe {
            std::ptr::copy_nonoverlapping(
                buffer.as_ptr(),
                self.buffer.add(self.offset),
                buffer.len(),
            );
            self.offset += buffer.len();
        }
    }

    fn offset(&self) -> usize {
        self.offset
    }

    fn align(&mut self, alignment: usize, with: u8) {
        let len = (alignment - self.offset % alignment) % alignment;
        assert!(
            self.offset.saturating_add(len) <= InterpreterGenerator::STEPS_SIZE,
            "0x{:x} 0x{:x} 0x{:x}",
            self.offset,
            len,
            InterpreterGenerator::STEPS_SIZE
        );
        unsafe {
            self.buffer.add(self.offset).write_bytes(with, len);
            self.offset += len;
        }
    }

    fn push(&mut self, byte: u8) {
        self.extend(&[byte])
    }

    fn push_i8(&mut self, value: i8) {
        self.extend(&[value as u8]);
    }

    fn push_i32(&mut self, value: i32) {
        self.extend(&value.to_le_bytes());
    }

    fn global_reloc(
        &mut self,
        name: &'static str,
        _target_offset: isize,
        _field_offset: u8,
        _ref_offset: u8,
        _kind: u8,
    ) {
        panic!("global reference to an unknown symbol {}", name);
    }

    fn template_reloc(&mut self, _: TemplateRelocationKind, _: isize, _: u8, _: u8) {
        // Intentionally empty: interpreter does not generate templates.
    }

    fn dynamic_reloc(
        &mut self,
        id: DynamicLabel,
        target_offset: isize,
        field_offset: u8,
        ref_offset: u8,
        kind: u8,
    ) {
        let patch = PatchFields::new(target_offset, field_offset, ref_offset, kind);
        self.relocs.dynamic_reloc(self.offset, id, patch);
    }

    fn new_dynamic_label(&mut self) -> DynamicLabel {
        self.relocs.new_dynamic_label()
    }

    fn dynamic_label(&mut self, id: DynamicLabel) {
        self.relocs.dynamic_label(id, self.offset);
    }

    fn insn(&self) -> TemplateInsn {
        with_machine_regs(self.insn)
    }

    fn supports(&self) -> &SupportingCode {
        &self.supports
    }

    fn bpf_taken_branch(&mut self) {
        x64asm!(self
            ; movsx RTEMP, WORD REL32_OFF
            ; lea RMETER, [ RMETER + RTEMP*8 ]
            ; lea RINSN, [ RINSN + RTEMP*8 ]
        );
        self.terminal = true;
    }
}

static INTERPRETER_AND_SUPPORTS: LazyLock<(Interpreter, SupportingCode)> = LazyLock::new(|| {
    let mut generator = InterpreterGenerator::new();
    let base_addr = i32::try_from(generator.buffer as usize).expect("interpreter in first 2GB");
    for insn in template_insns() {
        generator.insn = insn;
        let step_start = generator.offset;
        bpf_insn_template(&mut generator);
        generator.terminal = false;
        if insn_size(insn.op) == ebpf::INSN_SIZE {
            x64asm!(generator
                ; movzx RTEMP, WORD [ RINSN ]
                ; shl RTEMP, InterpreterGenerator::STEP_SIZE_LOG2 as i8
                ; lea RTEMP, [ DWORD base_addr + RTEMP ]
                ; add RINSN, 8
                ; jmp RTEMP
            );
        } else {
            let size = i8::try_from(insn_size(insn.op)).unwrap();
            // `insn` points at the second half.
            x64asm!(generator
                ; movzx RTEMP, WORD [ BYTE (size - 8) + RINSN ]
                ; shl RTEMP, InterpreterGenerator::STEP_SIZE_LOG2 as i8
                ; lea RTEMP, [ DWORD base_addr + RTEMP ]
                ; add RINSN, size as i32
                ; jmp RTEMP
            );
        }
        assert!(
            generator.offset - step_start <= 1 << InterpreterGenerator::STEP_SIZE_LOG2,
            "step for {:#x} is too long",
            insn.op
        );
        x64asm!(generator; .align 1 << InterpreterGenerator::STEP_SIZE_LOG2);
    }

    let buffer = unsafe {
        std::slice::from_raw_parts_mut(generator.buffer, InterpreterGenerator::STEPS_SIZE)
    };
    generator.relocs.resolve(buffer, Some(base_addr as usize));

    #[cfg(feature = "codegen_debug")]
    // EM_X86_64
    super::write_perf_jitdump(generator.buffer, InterpreterGenerator::STEPS_SIZE, 62);
    unsafe {
        libc::mprotect(
            generator.buffer.cast(),
            InterpreterGenerator::STEPS_SIZE,
            libc::PROT_READ | libc::PROT_EXEC,
        );
    }
    (
        Interpreter {
            buffer: generator.buffer,
        },
        generator.supports,
    )
});

/// Run the code at `start_addr` (machine code), with `vm.previous_instruction_meter` as the budget
/// and `insn` as the initial value of `RINSN`.
pub fn enter<C: crate::vm::ContextObject>(
    bpf: &[u8],
    start_addr: usize,
    insn: *const u8,
    vm: &mut crate::vm::EbpfVm<C>,
) {
    let entry_point = INTERPRETER_AND_SUPPORTS.1.entry_point;
    vm.call_depth = 0;
    vm.syscall_dispatcher = supporting_code::syscall_dispatcher::<C>();
    let meter = initial_meter(bpf, vm);
    let code: u64;
    let remaining: u64;
    unsafe {
        std::arch::asm!(
            "push rbx",
            "rdgsbase rbx",
            "push rbx",
            "wrgsbase rsi",
            "call r8",
            "pop rbx",
            "wrgsbase rbx",
            "pop rbx",
            // Explicit registers throughout: a `reg` operand could be allocated to `rbx`.
            inout("rsi") std::ptr::from_mut(vm) => _,
            inout("r8") entry_point => _,
            inout("rax") insn => _,
            inout("rcx") start_addr => code,
            inout("rdx") meter => remaining,
            lateout("rdi") _,
            lateout("r9") _,
            lateout("r10") _,
            lateout("r11") _,
            lateout("r12") _,
            lateout("r13") _,
            lateout("r14") _,
            lateout("r15") _,
        );
    }
    finish_execution(vm, code as i8, remaining);
}

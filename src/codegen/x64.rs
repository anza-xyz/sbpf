use dynasmrt::components::{LabelRegistry, PatchLoc, RelocRegistry, StaticLabel};
use dynasmrt::relocations::{Relocation, RelocationKind, SimpleRelocation};
use dynasmrt::{AssemblyOffset, DynamicLabel};

use crate::codegen::Template;
use crate::ebpf;
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

/// Size of the stack frame allocated for each internal call (fixed frames, as in SBPFv3.)
const STACK_FRAME_SIZE: i32 = 4096;
/// Maximum internal call depth (as in SBPFv3.)
const MAX_CALL_DEPTH: i32 = 64;

/// Size of the instruction with the opcode `op`, in bytes.
const fn insn_size(op: u8) -> usize {
    if op == ebpf::LD_DW_IMM {
        2 * ebpf::INSN_SIZE
    } else {
        ebpf::INSN_SIZE
    }
}

const SIG_INVALID_INSN: i8 = -1;
const SIG_EXCEEDED_MAX_INSTRUCTIONS: i8 = -2;
const SIG_CALL_DEPTH_EXCEEDED: i8 = -3;
const SIG_DIVIDE_BY_ZERO: i8 = -4;
const SIG_EXECUTION_OVERRUN: i8 = -5;
const SIG_CALL_OUTSIDE_TEXT_SEGMENT: i8 = -6;
/// `vm.program_result` has already been set.
const SIG_PROGRAM_RESULT: i8 = -7;

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
        x64asm!(@munch {$output; [ $($acc)* ] [ ; if ($output.op() & ebpf::BPF_X) == ebpf::BPF_X {
            x64asm!(@munch {$output; [;] [$($curr)*]} Rb($output.src()))
          } else {
            x64asm!(@munch {$output; [;] [$($curr)*]} BYTE REL32_IMM)
          }
        ]} $($rest)*)
    };
    (@munch {$output:expr; [$($acc:tt)*] [$($curr:tt)*]} ALU_SRC32 $($rest:tt)*) => {
        x64asm!(@munch {$output; [ $($acc)* ] [ ; if ($output.op() & ebpf::BPF_X) == ebpf::BPF_X {
            x64asm!(@munch {$output; [;] [$($curr)*]} Rd($output.src()))
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

    fn op(&self) -> u8;
    fn dst(&self) -> u8;
    fn src(&self) -> u8;
    fn supports(&self) -> &SupportingCode;

    // Generate code to handle branch taken case.
    fn bpf_taken_branch(&mut self);
}

/// Produce a template for a single (currently processed) instruction.
fn bpf_insn_template<G: X64Generator + ?Sized>(out: &mut G) {
    let is_alu64 = (out.op() & ebpf::BPF_CLS_MASK) == ebpf::BPF_ALU64_STORE;
    let dst = out.dst();
    let src = out.src();

    match out.op() {
        ebpf::NEG32 => x64asm!(out; neg Rd(dst)),
        ebpf::NEG64 => x64asm!(out; neg Rq(dst)),
        #[rustfmt::skip]
        ebpf::OR32_IMM |
        ebpf::OR32_REG => x64asm!(out; or Rd(dst), ALU_SRC32),
        ebpf::OR64_IMM => x64asm!(out
            ; mov WTEMP, ALU_SRC32
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
            ; mov WTEMP, ALU_SRC32
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
            ; mov WTEMP, ALU_SRC32
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
            let is_div = (out.op() & ebpf::BPF_ALU_OP_MASK) == ebpf::BPF_DIV;
            let is_reg = (out.op() & ebpf::BPF_X) == ebpf::BPF_X;
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
            let is_64 = (out.op() & ebpf::BPF_CLS_MASK) == ebpf::BPF_JMP64;
            let is_imm = (out.op() & ebpf::BPF_X) != ebpf::BPF_X;
            match (is_64, is_imm) {
                (true, true) => x64asm!(out
                    ; movsxd RTEMP, DWORD REL32_IMM
                    ; cmp Rq(dst), RTEMP
                ),
                (true, false) => x64asm!(out; cmp Rq(dst), Rq(src)),
                (false, true) => x64asm!(out; cmp Rd(dst), DWORD REL32_IMM),
                (false, false) => x64asm!(out; cmp Rd(dst), Rd(src)),
            }
            let fallthrough = out.new_dynamic_label();
            match out.op() & ebpf::BPF_ALU_OP_MASK {
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
            let kind = match out.op() & ebpf::BPF_CLS_MASK {
                ebpf::BPF_LDX => MemoryAccessKind::Load,
                ebpf::BPF_ST => MemoryAccessKind::StoreImm,
                ebpf::BPF_STX => MemoryAccessKind::StoreReg,
                _ => unreachable!(),
            };
            let size_log2 = match out.op() & ebpf::BPF_SIZE_MASK {
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

        ebpf::LMUL32_IMM
        | ebpf::LMUL32_REG
        | ebpf::SREM32_IMM
        | ebpf::SREM32_REG
        | ebpf::LMUL64_IMM
        | ebpf::LMUL64_REG
        | ebpf::SREM64_IMM
        | ebpf::SREM64_REG => {
            // TODO
            load_next_insn(out);
            terminate(out, SIG_INVALID_INSN)
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
        | 136..=140
        | 143..=147
        | 152..=155
        | 157
        | 160..=163
        | 168..=171
        | 176..=179
        | 184..=187
        | 192..=195
        | 200..=203
        | 208..=211
        | 215..=219
        | 223..=229
        | 231..=237
        | 239..=245
        | 248..=253
        | 255 => {
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

/// Save the registers that a `sysv64` host function call would clobber: the BPF registers are
/// spilled into `vm.registers`, the rest are pushed in the order of their register numbers (for
/// the internal registers that is `insn`, `temp`, `meter`.)
///
/// Returns the number of bytes pushed. The stack is not aligned for the call, see
/// `sysv64_call_needs_stack_alignment`. Does not touch the flags.
fn clobber_for_sysv64_call(out: &mut InterpreterGenerator) -> i32 {
    for (i, &reg) in GPREG_MAP.iter().enumerate() {
        if SYSV64_CLOBBERED & 1 << reg != 0 {
            x64asm!(out; gs mov [ RuntimeEnvironmentSlot::Registers as i32 + i as i32 * 8 ], Rq(reg));
        }
    }
    for reg in 0..16 {
        if SYSV64_PUSHED & 1 << reg != 0 {
            x64asm!(out; push Rq(reg));
        }
    }
    SYSV64_PUSHED.count_ones() as i32 * 8
}

/// Does `rsp` need to be adjusted by 8 bytes for a host function call, given the number of bytes
/// pushed since the BPF code? `rsp` is always `8 mod 16` in the BPF code.
const fn sysv64_call_needs_stack_alignment(pushed: i32) -> bool {
    pushed % 16 == 0
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
    for reg in (0..16).rev() {
        if SYSV64_PUSHED & 1 << reg != 0 {
            x64asm!(out; pop Rq(reg));
        }
    }
    for (i, &reg) in GPREG_MAP.iter().enumerate() {
        if SYSV64_CLOBBERED & 1 << reg != 0 {
            x64asm!(out; gs mov Rq(reg), [ RuntimeEnvironmentSlot::Registers as i32 + i as i32 * 8 ]);
        }
    }
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

/// Relocations against labels defined within the code being generated (local, global and dynamic
/// labels.)
///
/// These are resolved as soon as the code generation completes: for JIT that's when the template
/// is finalized, for the interpreter that's once all the steps have been generated.
struct LabelRelocs {
    labels: LabelRegistry,
    relocs: RelocRegistry<SimpleRelocation>,
}

impl LabelRelocs {
    fn new() -> Self {
        Self {
            labels: LabelRegistry::new(),
            relocs: RelocRegistry::new(),
        }
    }

    fn new_dynamic_label(&mut self) -> DynamicLabel {
        self.labels.new_dynamic_label()
    }

    fn dynamic_label(&mut self, id: DynamicLabel, at: usize) {
        self.labels.define_dynamic(id, AssemblyOffset(at)).unwrap()
    }

    fn global_reloc(&mut self, at: usize, name: &'static str, patch: PatchFields) {
        self.relocs
            .add_static(StaticLabel::global(name), patch.at(at));
    }

    fn global_label(&mut self, name: &'static str, at: usize) {
        self.labels.define_global(name, AssemblyOffset(at)).unwrap();
    }

    fn dynamic_reloc(&mut self, at: usize, id: DynamicLabel, patch: PatchFields) {
        self.relocs.add_dynamic(id, patch.at(at));
    }

    /// Patch all the recorded relocations into `buffer` and reset the label state.
    ///
    /// `buf_addr` is the address at which `buffer` will reside during execution. `None` means
    /// that the code is position independent and will get copied elsewhere, in which case only the
    /// relative relocations are supported.
    fn resolve(&mut self, buffer: &mut [u8], buf_addr: Option<usize>) {
        let patch = |loc: PatchLoc<SimpleRelocation>, target: AssemblyOffset, buffer: &mut [u8]| {
            if buf_addr.is_none() {
                assert!(
                    matches!(loc.relocation.kind(), RelocationKind::Relative),
                    "position independent code may only contain relative label references"
                );
            }
            let range = loc.range(0);
            loc.patch(&mut buffer[range], buf_addr.unwrap_or(0), target.0)
                .expect("impossible relocation");
        };
        for (loc, label) in self.relocs.take_statics() {
            let target = self.labels.resolve_static(&label).unwrap();
            patch(loc, target, buffer);
        }
        for (loc, id) in self.relocs.take_dynamics() {
            let target = self.labels.resolve_dynamic(id).unwrap();
            patch(loc, target, buffer);
        }
        self.labels.clear();
    }
}

/// Relocation parameters as produced by `dynasm`, sans the location.
#[derive(Clone, Copy)]
struct PatchFields {
    target_offset: isize,
    field_offset: u8,
    ref_offset: u8,
    relocation: SimpleRelocation,
}

impl PatchFields {
    fn new(target_offset: isize, field_offset: u8, ref_offset: u8, kind: u8) -> Self {
        Self {
            target_offset,
            field_offset,
            ref_offset,
            relocation: SimpleRelocation::from_encoding(kind),
        }
    }

    /// `at` is the offset right past the instruction containing the field to patch (i.e. the
    /// offset at the time `dynasm` reports the relocation.)
    fn at(self, at: usize) -> PatchLoc<SimpleRelocation> {
        PatchLoc::new(
            AssemblyOffset(at),
            self.target_offset,
            self.field_offset,
            self.ref_offset,
            self.relocation,
        )
    }
}

#[derive(Clone, Copy)]
enum TemplateRelocationKind {
    /// The JIT holds a pointer to the second instruction of the eBPF program in `insn`,
    /// whereas the templates default to addressing where `insn` is updated to point to right
    /// after the current instruction. This relocation adds the offset of the current instruction
    /// to the field.
    InsnOffset,
    /// When BPF instruction represents a branch, and the branch is taken, the control flow has to
    /// transfer to the machine code representing the target BPF instruction's code. Offset to this
    /// machine code is what this relocation must overwrite based on the BPF instruction being
    /// templated.
    TakenBranch,
    /// Offset (in bytes) from the instruction following the branch to the branch target.
    TakenBranchMeterAdjustment,
}

/// A relocation that can only be resolved once the template is instantiated for a specific eBPF
/// instruction at a specific location.
#[derive(Clone, Copy)]
struct TemplateRelocation {
    /// Offset within the template right past the instruction containing the field to patch.
    location: usize,
    patch: PatchFields,
    kind: TemplateRelocationKind,
}

impl TemplateRelocation {
    /// Patch the relocation into the instantiated template.
    ///
    /// `text` must be the buffer into which the template was copied, starting at `template_start`.
    /// `target` is an offset into `text` for relative relocations or the value to write for
    /// absolute ones.
    fn apply(&self, text: &mut [u8], template_start: usize, target: usize) {
        let loc = self.patch.at(template_start + self.location);
        let range = loc.range(0);
        loc.patch(&mut text[range], 0, target)
            .expect("impossible relocation");
    }
}

const MAX_JIT_TEMPLATE_SIZE: usize = 48;

struct JITGenerator {
    template: super::Template<MAX_JIT_TEMPLATE_SIZE, TemplateRelocation>,
    op: u8,
    dst: u8,
    src: u8,
    /// Temporary relocations within the code that will be resolved before the template is
    /// finalized.
    ///
    /// Template can have further relocations after finalization, however those relocations may only
    /// be specific to the eBPF instruction being instantiated.
    relocs: LabelRelocs,
    supports: &'static SupportingCode,
}

impl JITGenerator {
    pub fn new() -> Self {
        Self {
            template: super::Template::new(),
            op: 0,
            dst: 0,
            src: 0,
            relocs: LabelRelocs::new(),
            supports: &INTERPRETER_AND_SUPPORTS.1,
        }
    }

    /// Resolve all the relocations that can be resolved without knowing the specific eBPF
    /// instruction and return the template. The generator is reset to generate the next template.
    fn finalize(&mut self) -> Template<MAX_JIT_TEMPLATE_SIZE, TemplateRelocation> {
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

    fn op(&self) -> u8 {
        self.op
    }

    fn dst(&self) -> u8 {
        self.dst
    }

    fn src(&self) -> u8 {
        self.src
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
/// Machine code templates the JIT output is assembled from.
pub struct JitTemplates {
    /// Indexed by the lower 16 bits of an instruction.
    insns: Vec<Template<MAX_JIT_TEMPLATE_SIZE, TemplateRelocation>>,
    /// Appended after the last instruction, as if it was at `pc = program.len()`.
    execution_overrun: Template<MAX_JIT_TEMPLATE_SIZE, TemplateRelocation>,
    /// For `pc_section` entries that are not valid jump targets (e.g. the second
    /// halves of 16 byte instructions.)
    invalid_jump_target: Template<MAX_JIT_TEMPLATE_SIZE, TemplateRelocation>,
}

/// JIT templates for SBPFv3.
pub static JIT_TEMPLATES: LazyLock<JitTemplates> = LazyLock::new(|| {
    let mut insns = Vec::with_capacity(0x10000);
    let mut generator = JITGenerator::new();
    for bpf_src in 0..16 {
        for bpf_dst in 0..16 {
            for bpf_op in 0..=u8::MAX {
                generator.src = GPREG_MAP.get(bpf_src).copied().unwrap_or(u8::MAX);
                generator.dst = GPREG_MAP.get(bpf_dst).copied().unwrap_or(u8::MAX);
                generator.op = bpf_op;
                bpf_insn_template(&mut generator);
                insns.push(generator.finalize());
            }
        }
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

/// The JIT output for a program.
pub struct JitProgram {
    /// Offset in `text_section` for each BPF instruction.
    pub pc_section: Vec<u32>,
    /// The machine code.
    pub text_section: Vec<u8>,
}

impl JitTemplates {
    /// Compile `bpf` into machine code.
    ///
    /// Due to the time sensitive nature of this code we try to do minimal amount of work here.
    /// The result is a two pass algorithm where the first pass determines ahead of time where
    /// each instruction's machine code will be, allowing for e.g. forward jump relocations to be
    /// resolved immediately during the emission.
    pub fn compile(&self, bpf: &[u8]) -> JitProgram {
        let (program, rest) = bpf.as_chunks::<{ ebpf::INSN_SIZE }>();
        assert!(rest.is_empty());
        let mut text_section = Vec::<u8>::from(self.invalid_jump_target.buffer());
        let invalid_jump_target_loc = 0;

        let mut pc_section = Vec::with_capacity(program.len());
        let mut position = text_section.len();
        let mut program_iter = program.iter();
        while let Some(insn) = program_iter.next() {
            let insn_size = insn_size(insn[0]);
            let insn = u64::from_le_bytes(*insn);
            let template = &self.insns[insn as u16 as usize];
            pc_section.push(u32::try_from(position).expect("JIT output too large"));
            position += template.offset();
            for _ in 1..(insn_size / 8) {
                program_iter.next();
                pc_section.push(invalid_jump_target_loc);
            }
        }
        position += self.execution_overrun.offset();

        text_section.reserve(position - text_section.len());
        let mut emit = |pc, insn, template: &Template<_, TemplateRelocation>| {
            let template_start = text_section.len();
            text_section.extend_from_slice(template.buffer());
            for relocation in template.relocations() {
                let target = match relocation.kind {
                    TemplateRelocationKind::InsnOffset => pc * ebpf::INSN_SIZE,
                    TemplateRelocationKind::TakenBranchMeterAdjustment => {
                        let off = (insn >> 16) as i16;
                        (off as isize * ebpf::INSN_SIZE as isize) as usize
                    }
                    TemplateRelocationKind::TakenBranch => {
                        let off = (insn >> 16) as i16;
                        let target_pc = (pc as isize)
                            .checked_add(1 + off as isize)
                            .and_then(|target_pc| usize::try_from(target_pc).ok());
                        // FIXME: the verifier should have rejected these.
                        *target_pc
                            .and_then(|target_pc| pc_section.get(target_pc))
                            .expect("branch target out of bounds") as usize
                    }
                };
                relocation.apply(&mut text_section, template_start, target);
            }
        };
        let mut program_iter = program.iter().enumerate();
        while let Some((pc, insn)) = program_iter.next() {
            let insn = u64::from_le_bytes(*insn);
            for _ in 1..(insn_size(insn as u8) / 8) {
                program_iter.next();
            }
            emit(pc, insn, &self.insns[insn as u16 as usize]);
        }
        emit(program.len(), 0, &self.execution_overrun);
        JitProgram {
            pc_section,
            text_section,
        }
    }
}

/// Compile `bpf` and execute.
pub fn jit_and_run<C: crate::vm::ContextObject>(
    bpf: &[u8],
    bpf_vm_addr: u64,
    vm: &mut crate::vm::EbpfVm<C>,
) {
    let program = JIT_TEMPLATES.compile(bpf);
    let code = &program.text_section;
    let mut buffer = dynasmrt::mmap::MutableBuffer::new(code.len())
        .expect("failed to allocate executable memory for the JIT output");
    buffer.set_len(code.len());
    buffer.copy_from_slice(code);
    let buffer = buffer
        .make_exec()
        .expect("failed to make the JIT output executable");
    let start_addr =
        buffer.as_ptr() as usize + program.pc_section[vm.registers[11] as usize] as usize;
    vm.set_text_section(bpf, bpf_vm_addr);
    vm.jit_pc_section = program.pc_section.as_ptr();
    vm.jit_text_section = buffer.as_ptr();
    enter(
        bpf,
        start_addr,
        bpf.as_ptr().wrapping_add(ebpf::INSN_SIZE),
        vm,
    )
}

/// Interpret `bpf`.
pub fn interpret_and_run<C: crate::vm::ContextObject>(
    bpf: &[u8],
    bpf_vm_addr: u64,
    vm: &mut crate::vm::EbpfVm<C>,
) {
    let pc = vm.registers[11] as usize;
    let insn = &bpf[pc * ebpf::INSN_SIZE..][..2];
    let opcode = u16::from_le_bytes(<[u8; 2]>::try_from(insn).unwrap()) as usize;
    let address = unsafe {
        INTERPRETER_AND_SUPPORTS
            .0
            .buffer
            .add(opcode << InterpreterGenerator::STEP_SIZE_LOG2)
    };
    let insn = bpf.as_ptr().wrapping_add((pc + 1) * ebpf::INSN_SIZE);
    vm.set_text_section(bpf, bpf_vm_addr);
    vm.jit_pc_section = std::ptr::null();
    vm.jit_text_section = std::ptr::null();
    enter(bpf, address as usize, insn, vm)
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
    relocs: LabelRelocs,
    supports: SupportingCode,
    offset: usize,
    op: u8,
    dst: u8,
    src: u8,
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
                op: 0,
                dst: 0,
                src: 0,
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

    fn op(&self) -> u8 {
        self.op
    }

    fn dst(&self) -> u8 {
        self.dst
    }

    fn src(&self) -> u8 {
        self.src
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

/// Emit a perf jitdump (`/tmp/jit-<pid>.dump`) describing the interpreter buffer.
#[cfg(feature = "codegen_debug")]
fn write_perf_jitdump(ptr: *const u8, len: usize) {
    use std::io::Write as _;
    use std::os::fd::AsRawFd as _;
    unsafe {
        let pid = std::process::id();
        let tid = libc::syscall(libc::SYS_gettid) as u32;
        let now = || {
            let mut ts = libc::timespec {
                tv_sec: 0,
                tv_nsec: 0,
            };
            libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut ts);
            (ts.tv_sec as u64) * 1_000_000_000 + ts.tv_nsec as u64
        };

        let mut f = std::fs::File::create(format!("/tmp/jit-{pid}.dump")).unwrap();
        // 1. JIT Header (40 bytes)
        f.write_all(&0x4A495444u32.to_le_bytes()).unwrap(); // Magic: "JITD"
        f.write_all(&1u32.to_le_bytes()).unwrap(); // Version
        f.write_all(&40u32.to_le_bytes()).unwrap(); // Header size
        f.write_all(&62u32.to_le_bytes()).unwrap(); // ELF Machine: EM_X86_64
        f.write_all(&0u32.to_le_bytes()).unwrap(); // Pad
        f.write_all(&pid.to_le_bytes()).unwrap();
        f.write_all(&now().to_le_bytes()).unwrap();
        f.write_all(&0u64.to_le_bytes()).unwrap(); // Flags

        // Triggers perf record's MMAP detection
        let m = libc::mmap(
            std::ptr::null_mut(),
            4096,
            libc::PROT_READ | libc::PROT_EXEC,
            libc::MAP_PRIVATE,
            f.as_raw_fd(),
            0,
        );
        if m != libc::MAP_FAILED {
            libc::munmap(m, 4096);
        }

        // 2. JIT_CODE_LOAD Record Header (60 bytes = 56 byte record + 4 byte name)
        let rec_size = (60 + len) as u32;
        f.write_all(&0u32.to_le_bytes()).unwrap(); // ID: JIT_CODE_LOAD
        f.write_all(&rec_size.to_le_bytes()).unwrap();
        f.write_all(&now().to_le_bytes()).unwrap();
        f.write_all(&pid.to_le_bytes()).unwrap();
        f.write_all(&tid.to_le_bytes()).unwrap();
        f.write_all(&(ptr as u64).to_le_bytes()).unwrap(); // VMA
        f.write_all(&(ptr as u64).to_le_bytes()).unwrap(); // Code Address
        f.write_all(&(len as u64).to_le_bytes()).unwrap(); // Code Size
        f.write_all(&1u64.to_le_bytes()).unwrap(); // Index
        f.write_all(b"jit\0").unwrap(); // Symbol Name

        // 3. Raw Code Bytes
        f.write_all(std::slice::from_raw_parts(ptr, len)).unwrap();
    }
}

pub(super) static INTERPRETER_AND_SUPPORTS: LazyLock<(Interpreter, SupportingCode)> =
    LazyLock::new(|| {
        let mut generator = InterpreterGenerator::new();
        let base_addr = i32::try_from(generator.buffer as usize).expect("interpreter in first 2GB");
        for bpf_src in 0..16 {
            generator.src = GPREG_MAP.get(bpf_src).copied().unwrap_or(u8::MAX);
            for bpf_dst in 0..16 {
                generator.dst = GPREG_MAP.get(bpf_dst).copied().unwrap_or(u8::MAX);
                for bpf_op in 0..=u8::MAX {
                    generator.op = bpf_op;
                    let step_start = generator.offset;
                    bpf_insn_template(&mut generator);
                    generator.terminal = false;
                    if insn_size(bpf_op) == ebpf::INSN_SIZE {
                        x64asm!(generator
                            ; movzx RTEMP, WORD [ RINSN ]
                            ; shl RTEMP, InterpreterGenerator::STEP_SIZE_LOG2 as i8
                            ; lea RTEMP, [ DWORD base_addr + RTEMP ]
                            ; add RINSN, 8
                            ; jmp RTEMP
                        );
                    } else {
                        let size = i8::try_from(insn_size(bpf_op)).unwrap();
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
                        bpf_op
                    );
                    x64asm!(generator; .align 1 << InterpreterGenerator::STEP_SIZE_LOG2);
                }
            }
        }

        let buffer = unsafe {
            std::slice::from_raw_parts_mut(generator.buffer, InterpreterGenerator::STEPS_SIZE)
        };
        generator.relocs.resolve(buffer, Some(base_addr as usize));

        #[cfg(feature = "codegen_debug")]
        write_perf_jitdump(generator.buffer, InterpreterGenerator::STEPS_SIZE);
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

struct SupportingCode {
    /// Internal call trampoline, invoked (see `invoke_support`) with the host address of the
    /// target instruction in `temp`, and the address of the instruction to return to pushed
    /// beforehand.
    call_internal: *const u8,
    /// Syscall trampoline, invoked with the address of the instruction following the `CALL_IMM`
    /// in `temp`.
    syscall: *const u8,
    /// Memory access helpers, by `MemoryAccessKind` and log2 of the access size. See
    /// `SupportingCode::generate_memory_access_support`.
    memory_access: [[*const u8; 4]; 3],
    entry_point: *const u8,
    /// See `SupportingCode::divide`.
    divide: Vec<*const u8>,
}

unsafe impl Send for SupportingCode {}
unsafe impl Sync for SupportingCode {}

impl SupportingCode {
    /// Buffer space needed to generate this supporting code.
    const LEN: usize = 64 * 1024;

    /// `dst` and `src` are physical registers. `None` if either isn't a BPF register.
    fn divide_index(is_div: bool, is_64: bool, is_reg: bool, dst: u8, src: u8) -> Option<usize> {
        let bpf_reg = |reg| GPREG_MAP.iter().position(|&r| r == reg);
        let kind = is_div as usize | (is_64 as usize) << 1 | (is_reg as usize) << 2;
        let src = if is_reg { bpf_reg(src)? } else { 0 };
        Some((kind * GPREG_MAP.len() + bpf_reg(dst)?) * GPREG_MAP.len() + src)
    }

    /// Helper performing the division in place on the physical registers `dst` and `src` (or the
    /// immediate.) Expects the address of the instruction following the division in `temp`.
    fn divide(
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

    pub fn generate_into(out: &mut InterpreterGenerator) -> SupportingCode {
        // `[rsp + 24]` is the address of the instruction following the call, once the target is
        // pushed.
        let call_internal = unsafe { out.buffer.add(out.offset()) };
        let within_depth = out.new_dynamic_label();
        let in_bounds = out.new_dynamic_label();
        x64asm!(out
            ; push RTEMP
            ; mov RTEMP, [rsp + 24]
            ;; bpf_validate_meter(out)
            ; gs add QWORD [ RuntimeEnvironmentSlot::CallDepth as i32 ], 1
            ; gs cmp QWORD [ RuntimeEnvironmentSlot::CallDepth as i32 ], MAX_CALL_DEPTH
            ; jb =>within_depth
            ;; terminate(out, SIG_CALL_DEPTH_EXCEEDED)
            ; =>within_depth
            ; mov RTEMP, [rsp]
            ; gs sub RTEMP, [ RuntimeEnvironmentSlot::TextSection as i32 ]
            ; gs cmp RTEMP, [ RuntimeEnvironmentSlot::TextSectionLen as i32 ]
            ; jb =>in_bounds
            ; mov RTEMP, [rsp + 24]
            ;; terminate(out, SIG_CALL_OUTSIDE_TEXT_SEGMENT)
            ; =>in_bounds
            ; and RTEMP, -(ebpf::INSN_SIZE as i32)
        );

        // In the JIT, the machine code to call is found via `jit_pc_section`. Otherwise this is the
        // interpreter, and `insn` needs to point past the target instead.
        let base_addr = i32::try_from(out.buffer as usize).expect("interpreter in first 2GB");
        let interpreted = out.new_dynamic_label();
        let resolved = out.new_dynamic_label();
        x64asm!(out
            // `insn` is restored after the call: the JIT's never changes, and the interpreter's
            // is the instruction following the call.
            ; push RINSN
            ; gs add RTEMP, [ RuntimeEnvironmentSlot::TextSection as i32 ]
            ; mov [rsp + 8], RTEMP
            ; gs cmp QWORD [ RuntimeEnvironmentSlot::JitPcSection as i32 ], 0
            ; je =>interpreted
            // JIT specific: translate the jump address to a machine code address
            ; gs sub RTEMP, [ RuntimeEnvironmentSlot::TextSection as i32 ]
            ; shr RTEMP, 1
            ; gs add RTEMP, [ RuntimeEnvironmentSlot::JitPcSection as i32 ]
            ; mov WTEMP, [RTEMP]
            ; gs add RTEMP, [ RuntimeEnvironmentSlot::JitTextSection as i32 ]
            ; jmp =>resolved
            ; =>interpreted
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
            ; gs sub QWORD [ RuntimeEnvironmentSlot::CallDepth as i32 ], 1
            ; ret
        );

        let syscall = Self::generate_syscall_support(out);
        let kinds = [
            MemoryAccessKind::Load,
            MemoryAccessKind::StoreImm,
            MemoryAccessKind::StoreReg,
        ];
        let memory_access = kinds.map(|kind| {
            std::array::from_fn(|size_log2| {
                Self::generate_memory_access_support(out, kind, size_log2)
            })
        });

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

        // Expects `%gs` to point at the `EbpfVm`, `RINSN`, `RMETER` to be initialized and `RTEMP`
        // to be initialized to the address of the machine code to start executing at.
        let entry_point = unsafe { out.buffer.add(out.offset()) };
        let after_dispatch = out.new_dynamic_label();
        x64asm!(out
            ; push rbp
            ; mov rbp, rsp
            ; sub rsp, 16
            // `exit` jumps to `[rbp - 8]` from whatever depth of internal calls it's at.
            ; lea rsi, [ => after_dispatch ]
            ; mov [rbp - 8], rsi
        );
        for (i, &reg) in GPREG_MAP.iter().enumerate() {
            x64asm!(out; gs mov Rq(reg), [ RuntimeEnvironmentSlot::Registers as i32 + i as i32 * 8 ]);
        }
        x64asm!(out; call RTEMP);
        out.dynamic_label(after_dispatch);
        for (i, &reg) in GPREG_MAP.iter().enumerate() {
            x64asm!(out; gs mov [ RuntimeEnvironmentSlot::Registers as i32 + i as i32 * 8 ], Rq(reg));
        }
        x64asm!(out
            ; mov rsp, rbp
            ; pop rbp
            ; ret
        );

        Self {
            call_internal,
            syscall,
            memory_access,
            entry_point,
            divide,
        }
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
            ; rdgsbase rdi
            ; mov esi, [RTEMP - 4]
            // `rdx` is `meter`.
            ; sub rdx, RTEMP
            ; shr rdx, 3
        );
        if needs_stack_alignment {
            x64asm!(out; sub rsp, 8);
        }
        debug_assert_sysv64_call_stack_alignment(out);
        x64asm!(out; gs call QWORD [ RuntimeEnvironmentSlot::SyscallDispatcher as i32 ]);
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
            ; gs mov rdi, [ RuntimeEnvironmentSlot::MemoryMapping as i32 ]
            ; rdgsbase rax
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

/// Run the code at `start_addr` (machine code), with `vm.previous_instruction_meter` as the budget
/// and `insn` as the initial value of `RINSN`.
pub fn enter<C: crate::vm::ContextObject>(
    bpf: &[u8],
    start_addr: usize,
    insn: *const u8,
    vm: &mut crate::vm::EbpfVm<C>,
) {
    use crate::error::{EbpfError, ProgramResult};
    let entry_point = INTERPRETER_AND_SUPPORTS.1.entry_point;
    vm.call_depth = 0;
    vm.syscall_dispatcher = dispatch_syscall::<C> as *const u8;
    let pc = vm.registers[11];
    let budget = vm.previous_instruction_meter;
    let exec_limit = (bpf.as_ptr() as u64)
        .wrapping_add(pc.wrapping_add(budget).wrapping_mul(ebpf::INSN_SIZE as u64));
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
            inout("rdx") exec_limit => remaining,
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
    let code = code as i8;
    let remaining = if code == SIG_EXCEEDED_MAX_INSTRUCTIONS || (remaining as i64) < 0 {
        0
    } else {
        remaining / 8
    };
    // Syscalls consume the budget used up to them and update `previous_instruction_meter`.
    vm.due_insn_count = vm.previous_instruction_meter.saturating_sub(remaining);
    use EbpfError::*;
    match code {
        0 => vm.program_result = ProgramResult::Ok(vm.registers[0]),
        // Calls into Rust store their errors into `vm.program_result` themselves.
        SIG_PROGRAM_RESULT => {}
        SIG_EXCEEDED_MAX_INSTRUCTIONS => {
            vm.program_result = ProgramResult::Err(ExceededMaxInstructions)
        }
        SIG_INVALID_INSN => vm.program_result = ProgramResult::Err(UnsupportedInstruction),
        SIG_CALL_DEPTH_EXCEEDED => vm.program_result = ProgramResult::Err(CallDepthExceeded),
        SIG_DIVIDE_BY_ZERO => vm.program_result = ProgramResult::Err(DivideByZero),
        SIG_EXECUTION_OVERRUN => vm.program_result = ProgramResult::Err(ExecutionOverrun),
        SIG_CALL_OUTSIDE_TEXT_SEGMENT => {
            vm.program_result = ProgramResult::Err(CallOutsideTextSegment)
        }
        _ => unreachable!("unexpected exit code {}", code),
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

#[derive(Clone, Copy, PartialEq, Eq)]
enum MemoryAccessKind {
    Load,
    StoreImm,
    StoreReg,
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

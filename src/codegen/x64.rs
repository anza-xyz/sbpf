use dynasmrt::components::{LabelRegistry, PatchLoc, RelocRegistry, StaticLabel};
use dynasmrt::relocations::{Relocation, SimpleRelocation};
use dynasmrt::DynamicLabel;

use crate::codegen::{x64, Template};
use crate::ebpf;
use std::arch::naked_asm;
use std::convert::TryFrom;
use std::io::Write as _;
use std::os::fd::AsRawFd as _;
use std::sync::LazyLock;

const RAX: u8 = 0;
const RCX: u8 = 1;
const RDX: u8 = 2;
const RBX: u8 = 3;
const RSI: u8 = 6;
const RDI: u8 = 7;

/// Mapping from a numbered eBPF register to an x64 one.
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

const REG_INSN: u8 = RAX; // rax
const REG_TEMP: u8 = RCX; // rcx

const SIG_INVALID_INSN: i32 = -1;

/// Is the value in the provided register disposable/temporary?
pub const fn disposable_reg(reg: u8) -> bool {
    reg == REG_TEMP || reg == RDX
}

macro_rules! x64asm {
    ($output: expr; $($tts:tt)*) => { x64asm!(@munch {$output; [] []} ; $($tts)*) };
    (@munch {$output:expr; [$($acc:tt)*] [$($curr:tt)*]}) => {
        dynasm::dynasm!($output; .arch x64 $($acc)* $($curr)*)
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
            $($curr)* [ DWORD -4i32 + Rq(REG_INSN)] ;; $output.reloc_add_insn_off32()
        ]} $($rest)*)
    };

    (@munch {$output:expr; [$($acc:tt)*] [$($curr:tt)*]} REL32_OFF $($rest:tt)*) => {
        x64asm!(@munch {$output; [ $($acc)* ] [
            $($curr)* [DWORD -6i32 + Rq(REG_INSN)] ;; $output.reloc_add_insn_off32()
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
    fn align(&mut self, alignment: usize, with: u8);
    fn forward_reloc(
        &mut self,
        name: &'static str,
        target_offset: isize,
        field_offset: u8,
        ref_offset: u8,
        kind: u8,
    );
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
    fn new_dynamic_label(&mut self) -> Self::DynamicLabel;
    fn dynamic_label(&mut self, id: Self::DynamicLabel);

    fn op(&self) -> u8;
    fn dst(&self) -> u8;
    fn src(&self) -> u8;

    /// Terminate execution with the specified code.
    ///
    /// This will discard the guest code stack and return the exit code in REG_TEMP.
    fn exit(&mut self, code: i32);

    /// Introduce a relocation that, to the previous 4 bytes emitted, adds an offset to the
    /// beginning of the “current” eBPF instruction.
    ///
    /// This relocation type is intended to be used to augment memory operand displacements and
    /// exists because dynasm does not currently support this functionality natively. A
    /// straightforward example that adds the current instruction's immediate value to `rcx` is:
    ///
    /// ```
    /// dynasm!(output
    ///     ; add ecx, [ DWORD 4 + Rq(REG_INSN) ] ;; self.reloc_add_insn_off32()
    /// );
    /// ```
    ///
    /// This relocation type's implementation depends on how the generator uses the `REG_INSN`
    /// register. For interpreters which always maintain a pointer to the "current" instruction,
    /// this relocation type is a no-op. Meanwhile for JIT implementations that hold the pointer to
    /// the base of eBPF code, this should, effectively, produce a full offset.
    fn reloc_add_insn_off32(&mut self);

    /// Produce a template for a single (currently processed) instruction.
    fn bpf_insn_template(&mut self) {
        let is_alu64 = (self.op() & ebpf::BPF_CLS_MASK) == ebpf::BPF_ALU64_STORE;
        let op = self.op() & ebpf::BPF_ALU_OP_MASK;
        let dst = self.dst();
        let src = self.src();

        match self.op() {
            ebpf::NEG32 => x64asm!(self; neg Rd(dst)),
            ebpf::NEG64 => x64asm!(self; neg Rq(dst)),
            #[rustfmt::skip]
            ebpf::OR32_IMM |
            ebpf::OR32_REG => x64asm!(self; or Rd(dst), ALU_SRC32),
            ebpf::OR64_IMM => x64asm!(self
                ; mov Rd(REG_TEMP), ALU_SRC32
                ; or Rq(dst), Rq(REG_TEMP)
            ),
            #[rustfmt::skip]
            ebpf::OR64_REG => if dst != src { x64asm!(self
                ; or Rq(dst), Rq(src)
            )},
            ebpf::HOR64_IMM => x64asm!(self
                ; mov Rd(REG_TEMP), ALU_SRC32
                ; shl Rq(REG_TEMP), 32
                ; or Rq(dst), Rq(REG_TEMP)
            ),
            #[rustfmt::skip]
            ebpf::AND32_IMM |
            ebpf::AND32_REG => x64asm!(self; and Rd(dst), ALU_SRC32),
            #[rustfmt::skip]
            ebpf::AND64_IMM => x64asm!(self
                ; mov Rd(REG_TEMP), ALU_SRC32
                ; and Rq(dst), Rq(REG_TEMP)
            ),
            #[rustfmt::skip]
            ebpf::AND64_REG => if dst != src { x64asm!(self
                ; and Rq(dst), Rq(src)
            )},
            #[rustfmt::skip]
            ebpf::XOR32_IMM |
            ebpf::XOR32_REG => x64asm!(self; xor Rd(dst), ALU_SRC32),
            ebpf::XOR64_IMM => x64asm!(self
                ; mov Rd(REG_TEMP), ALU_SRC32
                ; xor Rq(dst), Rq(REG_TEMP)
            ),
            ebpf::XOR64_REG => x64asm!(self; xor Rq(dst), Rq(src)),
            ebpf::MOV32_IMM => x64asm!(self; mov Rd(dst), ALU_SRC32),
            ebpf::MOV64_IMM => x64asm!(self; movsxd Rq(dst), ALU_SRC32),
            ebpf::MOV32_REG => x64asm!(self; mov Rd(dst), Rd(src)),
            #[rustfmt::skip]
            ebpf::MOV64_REG => if src != dst { x64asm!(self
                ; mov Rq(dst), Rq(src)
            )},

            ebpf::ADD64_REG => x64asm!(self; add Rq(dst), Rq(src)),
            ebpf::SUB64_REG => x64asm!(self; sub Rq(dst), Rq(src)),
            ebpf::MUL64_REG => x64asm!(self; mulx Rq(dst), Rq(dst), Rq(src)),
            ebpf::ADD64_IMM => x64asm!(self
                ; movsxd Rq(REG_TEMP), REL32_IMM
                ; add Rq(dst), Rq(REG_TEMP)
            ),
            ebpf::SUB64_IMM => x64asm!(self
                ; movsxd Rq(REG_TEMP), REL32_IMM
                ; sub Rq(dst), Rq(REG_TEMP)
            ),
            ebpf::MUL64_IMM => x64asm!(self
                ; movsxd Rq(REG_TEMP), REL32_IMM
                ; mulx Rq(dst), Rq(dst), Rq(REG_TEMP)
            ),
            ebpf::ADD32_IMM | ebpf::ADD32_REG => x64asm!(self
                ; add Rd(dst), ALU_SRC32
                ; movsxd Rq(dst), Rd(dst)
            ),
            ebpf::SUB32_IMM | ebpf::SUB32_REG => x64asm!(self
                ; sub Rd(dst), ALU_SRC32
                ; movsxd Rq(dst), Rd(dst)
            ),
            ebpf::MUL32_IMM | ebpf::MUL32_REG => x64asm!(self
                ; mulx Rd(dst), Rd(dst), ALU_SRC32
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
                let result_reg = if is_div { RAX } else { RDX };
                const { assert!(disposable_reg(RDX) && !disposable_reg(RAX)); }
                assert!(dst != RAX);
                x64asm!(self
                    ; movsxd Rq(REG_TEMP), ALU_SRC32
                    ; movq xmm0, rax
                    ; mov eax, Rd(dst)
                    ; xor edx, edx
                );
                if is_alu64 { x64asm!(self
                    ; div Rq(REG_TEMP)
                    ; mov Rq(dst), Rq(result_reg)
                )} else { x64asm!(self
                    ; div Rd(REG_TEMP)
                    ; mov Rd(dst), Rd(result_reg)
                )}
                x64asm!(self
                    ; movq rax, xmm0
                );
            }
            ebpf::LSH64_IMM | ebpf::LSH64_REG => x64asm!(self
                // if failing, you can switch to shlx/shrx/sarx
                ;; const { assert!(disposable_reg(RCX)) }
                ; mov cl, ALU_SRC8
                ; shl Rq(dst), cl
            ),
            ebpf::LSH32_IMM | ebpf::LSH32_REG => x64asm!(self
                ;; const { assert!(disposable_reg(RCX)) }
                ; mov cl, ALU_SRC8
                ; shl Rd(dst), cl
            ),
            ebpf::RSH64_IMM | ebpf::RSH64_REG => x64asm!(self
                ;; const { assert!(disposable_reg(RCX)) }
                ; mov cl, ALU_SRC8
                ; shr Rq(dst), cl
            ),
            ebpf::RSH32_IMM | ebpf::RSH32_REG => x64asm!(self
                ;; const { assert!(disposable_reg(RCX)) }
                ; mov cl, ALU_SRC8
                ; shr Rd(dst), cl
            ),
            ebpf::ARSH64_IMM | ebpf::ARSH64_REG => x64asm!(self
                ;; const { assert!(disposable_reg(RCX)) }
                ; mov cl, ALU_SRC8
                ; sar Rq(dst), cl
            ),
            ebpf::ARSH32_IMM | ebpf::ARSH32_REG => x64asm!(self
                ;; const { assert!(disposable_reg(RCX)) }
                ; mov cl, ALU_SRC8
                ; sar Rd(dst), cl
            ),
            ebpf::BE => x64asm!(self
                ;; const { assert!(disposable_reg(RCX)) }
                ; xor ecx, ecx
                ; bswap Rq(dst)
                ; sub cl, ALU_SRC8
                ; shr Rq(dst), cl
            ),
            ebpf::LE => x64asm!(self
                ; mov Rd(REG_TEMP), ALU_SRC32
                ; bzhi Rq(dst), Rq(dst), Rq(REG_TEMP)
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
                let is_64 = (op & ebpf::BPF_CLS_MASK) == ebpf::BPF_JMP64;
                let is_imm = (op & ebpf::BPF_X) != ebpf::BPF_X;
                match (is_64, is_imm) {
                    (true, true) => x64asm!(self
                        ; movsxd Rq(REG_TEMP), DWORD REL32_IMM
                        ; cmp Rq(dst), Rq(REG_TEMP)
                    ),
                    (true, false) => x64asm!(self; cmp Rq(dst), Rq(src)),
                    (false, true) => x64asm!(self; cmp Rd(dst), DWORD REL32_IMM),
                    (false, false) => x64asm!(self; cmp Rd(dst), Rd(src)),
                }
                let fallthrough = self.new_dynamic_label();
                match op & ebpf::BPF_ALU_OP_MASK {
                    ebpf::BPF_JEQ => x64asm!(self; jne BYTE =>fallthrough),
                    ebpf::BPF_JGT => x64asm!(self; jbe BYTE =>fallthrough),
                    ebpf::BPF_JGE => x64asm!(self; jb BYTE =>fallthrough),
                    ebpf::BPF_JNE => x64asm!(self; je BYTE =>fallthrough),
                    ebpf::BPF_JSET => x64asm!(self; jz BYTE =>fallthrough),
                    ebpf::BPF_JSGT => x64asm!(self; jle BYTE =>fallthrough),
                    ebpf::BPF_JSGE => x64asm!(self; jl BYTE =>fallthrough),
                    ebpf::BPF_JLT => x64asm!(self; jae BYTE =>fallthrough),
                    ebpf::BPF_JLE => x64asm!(self; ja BYTE =>fallthrough),
                    ebpf::BPF_JSLT => x64asm!(self; jge BYTE =>fallthrough),
                    ebpf::BPF_JSLE => x64asm!(self; jg BYTE =>fallthrough),
                    _ => self.exit(SIG_INVALID_INSN),
                }
                self.bpf_taken_branch();
                self.dynamic_label(fallthrough);
            }
            ebpf::JA => self.bpf_taken_branch(),

            ebpf::CALL_IMM | ebpf::CALL_REG => x64asm!(self; int3),
            ebpf::EXIT => {
                x64asm!(self
                    ; xor Rd(REG_TEMP), Rd(REG_TEMP)
                    ; ret
                );
            }

            ebpf::LD_B_REG
            | ebpf::LD_H_REG
            | ebpf::LD_W_REG
            | ebpf::LD_DW_REG
            | ebpf::LD_DW_IMM
            | ebpf::ST_B_IMM
            | ebpf::ST_H_IMM
            | ebpf::ST_W_IMM
            | ebpf::ST_DW_IMM
            | ebpf::ST_B_REG
            | ebpf::ST_H_REG
            | ebpf::ST_W_REG
            | ebpf::ST_DW_REG => x64asm!(self; int3),

            ebpf::LMUL32_IMM
            | ebpf::LMUL32_REG
            | ebpf::SREM32_IMM
            | ebpf::SREM32_REG
            | ebpf::LMUL64_IMM
            | ebpf::LMUL64_REG
            | ebpf::SREM64_IMM
            | ebpf::SREM64_REG => x64asm!(self; int3),

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
            | 255 => self.exit(SIG_INVALID_INSN),
        }
    }

    // Generate code to handle branch taken case.
    fn bpf_taken_branch(&mut self);
}

#[derive(Clone, Copy)]
enum RelocationKind {
    // template_taken_branch relocation.
    //
    // When BPF instruction represents a branch, and the branch is taken, the control flow has to
    // transfer to the machine code representing the target BPF instruction's code. Offset to this
    // machine code is what this relocation must overwrite based on the BPF instruction being
    // templated.
    TakenBranch,
}

#[derive(Clone, Copy)]
struct TemplateRelocation {
    offset: usize,

    kind: RelocationKind,
}

#[derive(Clone, Copy)]
struct JITLabel {
    id: usize,
}

struct JITGenerator {
    template: super::Template<64, TemplateRelocation>,
    op: u8,
    dst: u8,
    src: u8,
    labels: [usize; 4], // offset to code where the label lies
    num_labels: usize,
    // Relocations in which we have to place the offset to the current instruction
    insn_offset_relocs: [usize; 16],
    num_insn_offset_relocs: usize,

    // FIXME: these have to be resolved as the template is finalized.
    dynamic_relocs: [usize; 16],
    num_dynamic_relocs: usize,
}

impl JITGenerator {
    pub const fn new() -> Self {
        Self {
            template: super::Template::new(),
            op: 0,
            dst: 0,
            src: 0,
            labels: [0; _],
            num_labels: 0,
            insn_offset_relocs: [0; _],
            num_insn_offset_relocs: 0,
            dynamic_relocs: [0; _],
            num_dynamic_relocs: 0,
        }
    }

    fn finalize(&mut self) -> Template<64, TemplateRelocation> {
        // TODO: fixup dynamic relocs...
        // the only ones to remain may be the insn_offset_relocs.
        self.template
    }
}

impl X64Generator for JITGenerator {
    type DynamicLabel = JITLabel;

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

    fn align(&mut self, alignment: usize, with: u8) {
        // Ignore alignment requests; we're generating templates.
    }

    fn forward_reloc(
        &mut self,
        name: &'static str,
        target_offset: isize,
        field_offset: u8,
        ref_offset: u8,
        kind: u8,
    ) {
        todo!()
    }

    fn new_dynamic_label(&mut self) -> JITLabel {
        assert!(self.num_labels < self.labels.len());
        let label = JITLabel {
            id: self.num_labels,
        };
        self.num_labels += 1;
        label
    }

    fn dynamic_label(&mut self, id: JITLabel) {
        self.labels[id.id] = self.offset();
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

    fn exit(&mut self, code: i32) {
        x64asm!(self
            ; mov Rq(REG_TEMP), code
            ; jmp QWORD [rbp - 8]
        );
    }

    fn reloc_add_insn_off32(&mut self) {
        let add_to = self.offset().checked_sub(4).unwrap();
        self.insn_offset_relocs[self.num_insn_offset_relocs] = add_to;
        self.num_insn_offset_relocs += 1;
    }

    fn bpf_taken_branch(&mut self) {
        x64asm!(self
            ; jmp ->template_taken_branch
        );
    }

    fn global_reloc(
        &mut self,
        name: &'static str,
        target_offset: isize,
        field_offset: u8,
        ref_offset: u8,
        kind: u8,
    ) {
        let ref_kind = kind >> 6;
        let ref_size = kind & 0x3F;
        match name {
            "template_taken_branch" => {
                assert!(target_offset == 0);
                assert!(ref_offset == 0);
                assert!(ref_kind == 0); // relative
                assert!(ref_size == 2); // dword
                self.template.add_relocation(TemplateRelocation {
                    offset: self.offset() + field_offset as usize,
                    kind: RelocationKind::TakenBranch,
                });
            }
            _ => panic!("unknown global reloc: {}", name),
        }
    }

    fn dynamic_reloc(
        &mut self,
        id: Self::DynamicLabel,
        target_offset: isize,
        field_offset: u8,
        ref_offset: u8,
        kind: u8,
    ) {
        assert!(target_offset == 0);
        // assert!(field_offset == 0);
        assert!(ref_offset == 0);
        assert!(kind == 0);
        self.dynamic_relocs[id.id] = self.offset() + field_offset as usize;
    }
}

// TODO: when dynasm supports const codegen, we can make these be generated at compile time into an
// array.
pub(super) static JIT_TEMPLATES: LazyLock<Vec<super::Template<64, TemplateRelocation>>> =
    LazyLock::new(|| {
        let mut result = Vec::with_capacity(0x10000);
        for bpf_src in 0..16 {
            for bpf_dst in 0..16 {
                for bpf_op in 0..=u8::MAX {
                    let mut generator = JITGenerator::new();
                    generator.src = GPREG_MAP.get(bpf_src).copied().unwrap_or(u8::MAX);
                    generator.dst = GPREG_MAP.get(bpf_dst).copied().unwrap_or(u8::MAX);
                    generator.op = bpf_op;
                    generator.bpf_insn_template();
                    result.push(generator.finalize());
                }
            }
        }
        result
    });

pub fn jit(bpf: &[u8]) -> Vec<u8> {
    let templates = &*JIT_TEMPLATES;
    assert!(bpf.as_ptr().cast::<u64>().is_aligned());
    assert!(bpf.len() % 8 == 0);
    let program: &[u64] = unsafe { bpf.align_to::<u64>().1 };
    let mut pc_section = Vec::<u32>::with_capacity(program.len());
    let mut position: u32 = 0;
    // first scan
    for op in program {
        let template = templates[*op as u16 as usize];
        pc_section.push(position);
        position += template.offset() as u32;
    }

    let mut text_section = Vec::<u8>::with_capacity(position as usize);
    // 2nd scan
    for op in program {
        let template = templates[*op as u16 as usize];
        // TODO: apply relocations.
        text_section.extend(template.buffer());
    }
    text_section
}

pub struct Interpreter {
    buffer: *mut u8,
    entrypoint: usize,
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
    interpreter: Interpreter,
    labels: dynasmrt::components::LabelRegistry,
    relocs: dynasmrt::components::RelocRegistry<SimpleRelocation>,
    offset: usize,
    op: u8,
    dst: u8,
    src: u8,
    generate_epilogue: bool,
    /// Is the code generated for this instruction terminal?
    ///
    /// No further instructions other than the epilogue expected to appear after this point.
    terminal: bool,
}

impl InterpreterGenerator {
    const STEP_SIZE_LOG2: u8 = 6; // 64 bytes
    const STEPS_SIZE: usize = 0x1_0000 * (1 << Self::STEP_SIZE_LOG2);

    pub fn new() -> Self {
        unsafe {
            let file = std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .create(true)
                .truncate(true)
                .open("interpreter.bin")
                .unwrap();
            file.set_len(Self::STEPS_SIZE as u64).unwrap();

            let buffer = libc::mmap(
                std::ptr::null_mut(),
                Self::STEPS_SIZE,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED | libc::MAP_32BIT,
                file.as_raw_fd(),
                0,
            );
            if buffer == libc::MAP_FAILED {
                panic!("libc::mmap failed to allocate executable memory for the interpreter");
            }
            let mut this = Self {
                interpreter: Interpreter {
                    buffer: buffer.cast(),
                    entrypoint: 0,
                },
                labels: LabelRegistry::new(),
                relocs: RelocRegistry::new(),
                offset: 0,
                op: 0,
                dst: 0,
                src: 0,
                generate_epilogue: true,
                terminal: false,
            };
            this.generate_helpers();
            this
        }
    }

    pub fn generate_helpers(&mut self) {
        // let old_offset = std::mem::replace(&mut self.offset, Self::STEPS_SIZE);
        // self.interpreter.entrypoint = self.offset;
        // self.entrypoint_helper();

        // self.offset = old_offset;
    }

    pub fn entrypoint_helper(&mut self) {
        // x64asm!(self
        //     ; int3
        // );
    }
}

impl X64Generator for InterpreterGenerator {
    type DynamicLabel = DynamicLabel;

    fn extend(&mut self, buffer: &[u8]) {
        assert!(!self.terminal);
        assert!(self.offset.saturating_add(buffer.len()) < InterpreterGenerator::STEPS_SIZE);
        let step_capacity = 1 << Self::STEP_SIZE_LOG2;
        let remaining_capacity = step_capacity - self.offset % step_capacity;
        assert!(buffer.len() <= remaining_capacity, "step is too long!");
        unsafe {
            std::ptr::copy_nonoverlapping(
                buffer.as_ptr(),
                self.interpreter.buffer.add(self.offset),
                buffer.len(),
            );
            self.offset += buffer.len();
        }
    }

    fn offset(&self) -> usize {
        self.offset
    }

    fn align(&mut self, alignment: usize, with: u8) {
        let len = ((self.offset % alignment)..alignment).len();
        assert!(
            self.offset.saturating_add(len) <= InterpreterGenerator::STEPS_SIZE,
            "0x{:x} 0x{:x} 0x{:x}",
            self.offset,
            len,
            InterpreterGenerator::STEPS_SIZE
        );
        unsafe {
            self.interpreter
                .buffer
                .add(self.offset)
                .write_bytes(with, len);
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

    fn forward_reloc(
        &mut self,
        name: &'static str,
        target_offset: isize,
        field_offset: u8,
        ref_offset: u8,
        kind: u8,
    ) {
        let location = dynasmrt::AssemblyOffset(self.offset);
        let label = match self.labels.place_local_reference(name) {
            Some(label) => label.next(),
            None => StaticLabel::first(name),
        };
        let reloc = SimpleRelocation::from_encoding(kind);
        let patchloc = PatchLoc::new(location, target_offset, field_offset, ref_offset, reloc);
        self.relocs.add_static(label, patchloc);
    }

    fn global_reloc(
        &mut self,
        name: &'static str,
        target_offset: isize,
        field_offset: u8,
        ref_offset: u8,
        kind: u8,
    ) {
        let location = dynasmrt::AssemblyOffset(self.offset);
        let label = StaticLabel::global(name);
        let reloc = SimpleRelocation::from_encoding(kind);
        let patchloc = PatchLoc::new(location, target_offset, field_offset, ref_offset, reloc);
        self.relocs.add_static(label, patchloc);
    }
    fn dynamic_reloc(
        &mut self,
        id: DynamicLabel,
        target_offset: isize,
        field_offset: u8,
        ref_offset: u8,
        kind: u8,
    ) {
        let location = dynasmrt::AssemblyOffset(self.offset);
        let reloc = SimpleRelocation::from_encoding(kind);
        let patchloc = PatchLoc::new(location, target_offset, field_offset, ref_offset, reloc);
        self.relocs.add_dynamic(id, patchloc);
    }

    fn new_dynamic_label(&mut self) -> DynamicLabel {
        self.labels.new_dynamic_label()
    }

    fn dynamic_label(&mut self, id: DynamicLabel) {
        self.labels
            .define_dynamic(id, dynasmrt::AssemblyOffset(self.offset))
            .unwrap()
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

    fn exit(&mut self, code: i32) {
        x64asm!(self
            ; mov Rq(REG_TEMP), code
            ; jmp QWORD [rbp - 8]
        );
        self.generate_epilogue = false;
        self.terminal = true;
    }

    fn reloc_add_insn_off32(&mut self) {
        // Intentionally empty: interpreter maintains current register's location in `INSN_REG`.
    }

    fn bpf_taken_branch(&mut self) {
        x64asm!(self
            ; movsx Rq(REG_TEMP), WORD REL32_OFF
            ; lea Rq(REG_INSN), [ Rq(REG_INSN) + Rq(REG_TEMP)*8 ]
        );
        self.terminal = true;
    }
}

pub(super) static INTERPRETER: LazyLock<Interpreter> = LazyLock::new(|| {
    let mut generator = InterpreterGenerator::new();
    let base_addr =
        i32::try_from(generator.interpreter.buffer as usize).expect("interpreter in first 2GB");

    for bpf_src in 0..16 {
        generator.src = GPREG_MAP.get(bpf_src).copied().unwrap_or(u8::MAX);
        for bpf_dst in 0..16 {
            generator.dst = GPREG_MAP.get(bpf_dst).copied().unwrap_or(u8::MAX);
            for bpf_op in 0..=u8::MAX {
                generator.op = bpf_op;
                generator.generate_epilogue = true;
                generator.bpf_insn_template();
                generator.terminal = false;
                if generator.generate_epilogue {
                    x64asm!(generator
                        ; movzx Rq(REG_TEMP), WORD [ Rq(REG_INSN) ]
                        ; shl Rq(REG_TEMP), InterpreterGenerator::STEP_SIZE_LOG2 as i8
                        ; lea Rq(REG_TEMP), [ DWORD base_addr + Rq(REG_TEMP) ]
                        ; add Rq(REG_INSN), 8
                        ; jmp Rq(REG_TEMP)
                    );
                }
                x64asm!(generator; .align 64);
            }
        }
    }

    for (loc, label) in generator.relocs.take_statics() {
        let target = generator.labels.resolve_static(&label).unwrap();
        let buf = unsafe {
            std::slice::from_raw_parts_mut(
                generator.interpreter.buffer.add(loc.range(0).start),
                loc.range(0).len(),
            )
        };
        if loc.patch(buf, base_addr as usize, target.0).is_err() {
            panic!("impossible relocation");
        }
    }

    for (loc, id) in generator.relocs.take_dynamics() {
        let target = generator.labels.resolve_dynamic(id).unwrap();
        let buf = unsafe {
            std::slice::from_raw_parts_mut(
                generator.interpreter.buffer.add(loc.range(0).start),
                loc.range(0).len(),
            )
        };
        if loc.patch(buf, base_addr as usize, target.0).is_err() {
            panic!("impossible relocation");
        }
    }

    unsafe {
        let ptr = generator.interpreter.buffer;
        let len = InterpreterGenerator::STEPS_SIZE;
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

        libc::mprotect(
            generator.interpreter.buffer.cast(),
            InterpreterGenerator::STEPS_SIZE,
            libc::PROT_READ | libc::PROT_EXEC,
        );
    }
    generator.interpreter
});

/// Interpret the bpf buffer.
pub extern "sysv64" fn interpret(bpf: &[u8]) {
    let first_opcode = u16::from_le_bytes(<[u8; 2]>::try_from(&bpf[0..2]).unwrap()) as usize;
    let address = unsafe {
        INTERPRETER
            .buffer
            .add(first_opcode << InterpreterGenerator::STEP_SIZE_LOG2)
    };
    enter(bpf, address as usize)
}

#[unsafe(naked)]
pub extern "sysv64" fn enter(bpf: &[u8], start_addr: usize) {
    // This function is meant to only do the bare minimum setup for the runtime to operate.
    // e.g. it will setup the VM pointer, stash the registers and setup rbp, but it won't e.g. deal
    // with writing the return value into the VM.
    naked_asm!(
        // TODO: only really need to save callee saved registers.
        "push rbp",
        "mov rbp, rsp",
        "sub rsp, 176",
        "mov    [rbp - 24],  rax",
        "mov    [rbp - 32],  rcx",
        "mov    [rbp - 40],  rdx",
        "mov    [rbp - 48],  rbx",
        "mov    [rbp - 56],  rsi",
        "mov    [rbp - 64],  rdi",
        "mov    [rbp - 72],  r8",
        "mov    [rbp - 80],  r9",
        "mov    [rbp - 88],  r10",
        "mov    [rbp - 96],  r11",
        "mov    [rbp - 104], r12",
        "mov    [rbp - 112], r13",
        "mov    [rbp - 120], r14",
        "mov    [rbp - 128], r15",
        "movdqa [rbp - 144], xmm0",
        "movdqa [rbp - 160], xmm1",
        // the "longjmp" destination address for signals
        "lea    rcx, [rip+0f]",
        "mov    qword ptr [rbp - 8], rcx",
        // Initialize "internal" registers.
        "mov rax, rdi",
        "mov rcx, rdx",
        // TODO: populate initial register values from VM
        "xor esi, esi",
        "xor edi, edi",
        "xor edx, edx",
        "xor ebx, ebx",
        "xor r8, r8",
        "xor r9, r9",
        "xor r10, r10",
        "xor r11, r11",
        "xor r12, r12",
        "xor r13, r13",
        "xor r14, r14",
        "xor r15, r15",
        "call 1f",
        "0:",
        "mov    rax,  [rbp - 24]",
        "mov    rcx,  [rbp - 32]",
        "mov    rdx,  [rbp - 40]",
        "mov    rbx,  [rbp - 48]",
        "mov    rsi,  [rbp - 56]",
        "mov    rdi,  [rbp - 64]",
        "mov    r8,   [rbp - 72]",
        "mov    r9,   [rbp - 80]",
        "mov    r10,  [rbp - 88]",
        "mov    r11,  [rbp - 96]",
        "mov    r12,  [rbp - 104]",
        "mov    r13,  [rbp - 112]",
        "mov    r14,  [rbp - 120]",
        "mov    r15,  [rbp - 128]",
        "movdqa xmm0, [rbp - 144]",
        "movdqa xmm1, [rbp - 160]",
        // Done, return to the caller.
        "mov rsp, rbp",
        "pop rbp",
        "ret",
        "1:",
        "jmp rcx",
    )
}

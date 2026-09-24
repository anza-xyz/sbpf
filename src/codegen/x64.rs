use dynasmrt::DynamicLabel;
use dynasmrt::components::{LabelRegistry, PatchLoc, RelocRegistry, StaticLabel};
use dynasmrt::relocations::{Relocation, SimpleRelocation};

use crate::codegen::{x64, Buffer, Opcode, Template};
use crate::ebpf;
use std::convert::TryFrom;
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
            $($curr)* [DWORD 4 + Rq(REG_INSN)] ;; $output.reloc_add_insn_off32()
        ]} $($rest)*)
    };

    (@munch {$output:expr; [$($acc:tt)*] [$($curr:tt)*]} REL32_OFF $($rest:tt)*) => {
        x64asm!(@munch {$output; [ $($acc)* ] [
            $($curr)* [DWORD 2 + Rq(REG_INSN)] ;; $output.reloc_add_insn_off32()
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
        id: DynamicLabel,
        target_offset: isize,
        field_offset: u8,
        ref_offset: u8,
        kind: u8,
    );
    fn new_dynamic_label(&mut self) -> DynamicLabel;
    fn local_label(&mut self, name: &'static str);
    fn dynamic_label(&mut self, id: DynamicLabel);

    fn op(&self) -> u8;
    fn dst(&self) -> u8;
    fn src(&self) -> u8;

    /// This instruction is invalid.
    fn invalid_insn(&mut self);

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
                    _ => self.invalid_insn(),
                }
                self.bpf_taken_branch(fallthrough);
            }
            ebpf::JA => {
                let _unused_label = self.new_dynamic_label();
                self.bpf_taken_branch(_unused_label)
            },

            ebpf::CALL_IMM | ebpf::CALL_REG => x64asm!(self; int3),
            ebpf::EXIT => x64asm!(self; ret),

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
            | 255 => self.invalid_insn(),
        }
    }

    // Generate code to handle branch taken case.
    fn bpf_taken_branch(&mut self, fallthrough: DynamicLabel);
}

struct JITGenerator {}

impl X64Generator for JITGenerator {
    fn extend(&mut self, buffer: &[u8]) {
        todo!()
    }

    fn offset(&self) -> usize {
        todo!()
    }

    fn push(&mut self, byte: u8) {
        todo!()
    }

    fn push_i32(&mut self, value: i32) {
        todo!()
    }

    fn push_i8(&mut self, value: i8) {
        todo!()
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


    fn new_dynamic_label(&mut self) -> DynamicLabel {
        todo!()
    }

    fn local_label(&mut self, name: &'static str) {
        todo!()
    }
    fn dynamic_label(&mut self, id: DynamicLabel) {
        todo!()
    }

    fn op(&self) -> u8 {
        todo!()
    }

    fn dst(&self) -> u8 {
        todo!()
    }

    fn src(&self) -> u8 {
        todo!()
    }

    fn invalid_insn(&mut self) {
        x64asm!(self; jmp ->invalid_insn);
    }

    fn reloc_add_insn_off32(&mut self) {
        let add_to = self.offset().checked_sub(4).unwrap();
        todo!("add the current insn offset to add_to={add_to}")
    }

    fn bpf_taken_branch(&mut self, fallthrough: DynamicLabel) {
        todo!()
    }

    fn align(&mut self, alignment: usize, with: u8) {
        todo!()
    }

    fn global_reloc(
        &mut self,
        name: &'static str,
        target_offset: isize,
        field_offset: u8,
        ref_offset: u8,
        kind: u8,
    ) {
        todo!()
    }

    fn dynamic_reloc(
        &mut self,
        id: DynamicLabel,
        target_offset: isize,
        field_offset: u8,
        ref_offset: u8,
        kind: u8,
    ) {
        todo!()
    }
}

// TODO: when dynasm supports const codegen, we can make these be generated at compile time into an
// array.
// pub(super) static JIT_TEMPLATES: LazyLock<Vec<super::Template<64>>> = LazyLock::new(|| {
//     let mut result = Vec::with_capacity(u16::MAX as usize);
//     for bpf_src in 0..16 {
//         for bpf_dst in 0..16 {
//             for bpf_op in 0..=u8::MAX {
//                 let mut template = Template::new();
//                 let (Some(src), Some(dst)) = (GPREG_MAP.get(bpf_src), GPREG_MAP.get(bpf_dst))
//                 else {
//                     result.push(template);
//                     continue;
//                 };
//                 // generate_opcode_template(&mut template, bpf_op, *src, *dst);
//                 result.push(template);
//             }
//         }
//     }
//     assert!(
//         result.len() == u16::MAX as usize,
//         "must generate a template for each of the thingies"
//     );
//     result
// });

pub struct Interpreter {
    buffer: *mut u8,
    entrypoint: usize,
}

unsafe impl Send for Interpreter {}
unsafe impl Sync for Interpreter {}

impl Drop for Interpreter {
    fn drop(&mut self) {
        unsafe {
            libc::munmap(
                self.buffer.cast(),
                InterpreterGenerator::STEPS_SIZE + InterpreterGenerator::HELPERS_SIZE,
            );
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
    const HELPERS_SIZE: usize = 10240;

    pub fn new() -> Self {
        unsafe {
            let buffer = libc::mmap(
                std::ptr::null_mut(),
                Self::STEPS_SIZE + Self::HELPERS_SIZE,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | libc::MAP_32BIT,
                -1,
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

    fn local_label(&mut self, name: &'static str) {
        self.labels
            .define_local(name, dynasmrt::AssemblyOffset(self.offset));
    }
    fn dynamic_label(&mut self, id: DynamicLabel) {
        self.labels.define_dynamic(id, dynasmrt::AssemblyOffset(self.offset)).unwrap()
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

    fn invalid_insn(&mut self) {
        x64asm!(self
            // TODO: something of this sort, returning straight back to the runtime exit point,
            // pretty much a longjmp?
            ; mov rsp, rbp
            ; ret
        );
        self.generate_epilogue = false;
        self.terminal = true;
    }

    fn reloc_add_insn_off32(&mut self) {
        // Intentionally empty: interpreter maintains current register's location in `INSN_REG`.
    }

    fn bpf_taken_branch(&mut self, fallthrough: DynamicLabel) {
        let base_addr =
            i32::try_from(self.interpreter.buffer as usize).expect("interpreter in first 2GB");
        x64asm!(self
            ; movsx Rq(REG_TEMP), WORD [ Rq(REG_INSN) + 2i8 ]
            ; lea Rq(REG_INSN), [ Rq(REG_INSN) + Rq(REG_TEMP)*8 + 8 ]
            ; => fallthrough
            ; movzx Rq(REG_TEMP), WORD [ Rq(REG_INSN) ]
            ; shl Rq(REG_TEMP), InterpreterGenerator::STEP_SIZE_LOG2 as i8
            ; lea Rq(REG_TEMP), [ DWORD base_addr + Rq(REG_TEMP) ]
            ; jmp Rq(REG_TEMP)
        );
        self.terminal = true;
        self.generate_epilogue = false;
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
                        ; add Rq(REG_INSN), 8
                        ; movzx Rq(REG_TEMP), WORD [ Rq(REG_INSN) ]
                        ; shl Rq(REG_TEMP), InterpreterGenerator::STEP_SIZE_LOG2 as i8
                        ; lea Rq(REG_TEMP), [ DWORD base_addr + Rq(REG_TEMP) ]
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
        libc::mprotect(
            generator.interpreter.buffer.cast(),
            InterpreterGenerator::STEPS_SIZE,
            libc::PROT_READ | libc::PROT_EXEC,
        );
    }
    generator.interpreter
});

pub fn enter(bpf: &[u8]) {
    let mut r = [0; 10];
    let mut rax = bpf.as_ptr() as usize;
    let mut rcx = INTERPRETER.buffer as usize;
    let mut rdx = 0;

    unsafe {
        std::arch::asm!(
            "push rbp",
            "mov rbp, rsp",
            "push rbx",
            "movzx rbx, word ptr [rax]",
            "shl rbx, 6",
            "lea rcx, [ rcx + rbx ]",
            "xor ebx, ebx",
            "call rcx",
            "pop rbx",
            "pop rbp",
            inout("rax") rax,
            inout("rcx") rcx,
            inout("rdx") rdx,
            inout("rsi") r[0],
            inout("rdi") r[1],
            inout("r8") r[2],
            inout("r9") r[3],
            inout("r10") r[4],
            inout("r11") r[5],
            inout("r12") r[6],
            inout("r13") r[7],
            inout("r14") r[8],
            inout("r15") r[9],
            out("xmm0") _,
        )
    }
    println!("{:?}", r);
    let _ = (r, rax, rcx, rdx);
}

#[cfg(test)]
mod tests {
    use crate::codegen::x64::{InterpreterGenerator, INTERPRETER};

    #[test]
    fn dump_interpreter_code() {
        unsafe {
            std::fs::write(
                "code.bin",
                std::slice::from_raw_parts(
                    INTERPRETER.buffer.cast_const(),
                    InterpreterGenerator::STEPS_SIZE,
                ),
            )
            .unwrap();
        }
    }
}

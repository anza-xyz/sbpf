use dynasmrt::components::{LabelRegistry, PatchLoc, RelocRegistry, StaticLabel};
use dynasmrt::relocations::{Relocation, RelocationKind, SimpleRelocation};
use dynasmrt::{AssemblyOffset, DynamicLabel};

use crate::codegen::Template;
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

// Keep in sync with the `temp` `.alias` in `x64asm!`.
const REG_TEMP: u8 = RCX; // rcx

/// Size of the stack frame allocated for each internal call (fixed frames, as in SBPFv3.)
const STACK_FRAME_SIZE: i32 = 4096;

const SIG_INVALID_INSN: i8 = -1;
const SIG_EXCEEDED_MAX_INSTRUCTIONS: i8 = -2;

/// Is the value in the provided register disposable/temporary?
pub const fn disposable_reg(reg: u8) -> bool {
    reg == REG_TEMP
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

    (@munch {$output:expr; [$($acc:tt)*] [$($curr:tt)*]} REL32_NEXT_INSN $($rest:tt)*) => {
        x64asm!(@munch {$output; [ $($acc)* ] [
            $($curr)* [ DWORD 0i32 + RINSN ] ;; $output.template_reloc(TemplateRelocationKind::InsnOffset, 0, 4, 0)
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

    /// Produce a template for a single (currently processed) instruction.
    fn bpf_insn_template(&mut self) {
        let is_alu64 = (self.op() & ebpf::BPF_CLS_MASK) == ebpf::BPF_ALU64_STORE;
        let dst = self.dst();
        let src = self.src();

        match self.op() {
            ebpf::NEG32 => x64asm!(self; neg Rd(dst)),
            ebpf::NEG64 => x64asm!(self; neg Rq(dst)),
            #[rustfmt::skip]
            ebpf::OR32_IMM |
            ebpf::OR32_REG => x64asm!(self; or Rd(dst), ALU_SRC32),
            ebpf::OR64_IMM => x64asm!(self
                ; mov WTEMP, ALU_SRC32
                ; or Rq(dst), RTEMP
            ),
            #[rustfmt::skip]
            ebpf::OR64_REG => if dst != src { x64asm!(self
                ; or Rq(dst), Rq(src)
            )},
            ebpf::HOR64_IMM => x64asm!(self
                ; mov WTEMP, ALU_SRC32
                ; shl RTEMP, 32
                ; or Rq(dst), RTEMP
            ),
            #[rustfmt::skip]
            ebpf::AND32_IMM |
            ebpf::AND32_REG => x64asm!(self; and Rd(dst), ALU_SRC32),
            #[rustfmt::skip]
            ebpf::AND64_IMM => x64asm!(self
                ; mov WTEMP, ALU_SRC32
                ; and Rq(dst), RTEMP
            ),
            #[rustfmt::skip]
            ebpf::AND64_REG => if dst != src { x64asm!(self
                ; and Rq(dst), Rq(src)
            )},
            #[rustfmt::skip]
            ebpf::XOR32_IMM |
            ebpf::XOR32_REG => x64asm!(self; xor Rd(dst), ALU_SRC32),
            ebpf::XOR64_IMM => x64asm!(self
                ; mov WTEMP, ALU_SRC32
                ; xor Rq(dst), RTEMP
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
                ; movsxd RTEMP, REL32_IMM
                ; add Rq(dst), RTEMP
            ),
            ebpf::SUB64_IMM => x64asm!(self
                ; movsxd RTEMP, REL32_IMM
                ; sub Rq(dst), RTEMP
            ),
            ebpf::MUL64_IMM => x64asm!(self
                ; movsxd RTEMP, REL32_IMM
                ; mulx Rq(dst), Rq(dst), RTEMP
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
                let is_div = (self.op() & ebpf::BPF_ALU_OP_MASK) == ebpf::BPF_DIV;
                let result_reg = if is_div { RAX } else { RDX };
                assert!(dst != RAX && dst != RDX);
                x64asm!(self
                    ; movsxd RTEMP, ALU_SRC32
                    ; movq xmm0, rax
                    ; movq xmm1, rdx
                    ; mov eax, Rd(dst)
                    ; xor edx, edx
                );
                if is_alu64 { x64asm!(self
                    ; div RTEMP
                    ; mov Rq(dst), Rq(result_reg)
                )} else { x64asm!(self
                    ; div WTEMP
                    ; mov Rd(dst), Rd(result_reg)
                )}
                x64asm!(self
                    ; movq rax, xmm0
                    ; movq rdx, xmm1
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
                self.bpf_validate_meter();
                let is_64 = (self.op() & ebpf::BPF_CLS_MASK) == ebpf::BPF_JMP64;
                let is_imm = (self.op() & ebpf::BPF_X) != ebpf::BPF_X;
                match (is_64, is_imm) {
                    (true, true) => x64asm!(self
                        ; movsxd RTEMP, DWORD REL32_IMM
                        ; cmp Rq(dst), RTEMP
                    ),
                    (true, false) => x64asm!(self; cmp Rq(dst), Rq(src)),
                    (false, true) => x64asm!(self; cmp Rd(dst), DWORD REL32_IMM),
                    (false, false) => x64asm!(self; cmp Rd(dst), Rd(src)),
                }
                let fallthrough = self.new_dynamic_label();
                match self.op() & ebpf::BPF_ALU_OP_MASK {
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

            // SBPFv3 internal call: target is `next + imm`.
            ebpf::CALL_IMM if src == GPREG_MAP[1] => {
                self.bpf_validate_meter();
                // Save r6-r9 and the frame pointer (r10), then allocate a new frame.
                x64asm!(self
                    ; push R6
                    ; push R7
                    ; push R8
                    ; push R9
                    ; push R10
                    ; add R10, STACK_FRAME_SIZE
                    ; push RINSN
                );
                self.bpf_internal_call();
                x64asm!(self
                    ; pop RINSN
                    // `EXIT` leaves the remaining budget in `meter`, convert it back into the
                    // limit relative to the instruction following this call.
                    ; lea RTEMP, REL32_NEXT_INSN
                    ; add RMETER, RTEMP
                    ; pop R10
                    ; pop R9
                    ; pop R8
                    ; pop R7
                    ; pop R6
                );
            }
            ebpf::CALL_IMM | ebpf::CALL_REG => x64asm!(self; int3),
            ebpf::EXIT => {
                self.bpf_validate_meter();
                x64asm!(self
                    ; sub RMETER, RTEMP
                    ; xor WTEMP, WTEMP
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

    /// Adjust the instruction meter for, and call, the target of an internal call.
    ///
    /// The callee returns here when it executes `EXIT`.
    fn bpf_internal_call(&mut self);

    /// Terminate execution with the specified code.
    ///
    /// This will discard the guest code stack and return the exit code in `temp` and the
    /// remaining instruction budget in `meter`.
    fn exit(&mut self, code: i8) {
        if code != SIG_EXCEEDED_MAX_INSTRUCTIONS {
            // Update `meter` only when we don't know that the remainder is already 0. Callers can
            // check the return code and determine if they need to interpret the remainder without
            // cluttering every point in generated JIT code.
            x64asm!(self
                ; lea RTEMP, REL32_NEXT_INSN
                ; sub RMETER, RTEMP
            );
        }
        x64asm!(self
            ; mov BTEMP, code
            ; jmp QWORD [rbp - 8]
        );
    }

    /// Terminate the execution if the instruction budget has been exceeded.
    ///
    /// `temp` contains the address of the next BPF instruction.
    fn bpf_validate_meter(&mut self) {
        let within_budget = self.new_dynamic_label();
        x64asm!(self
            ; lea RTEMP, REL32_NEXT_INSN
            ; cmp RTEMP, RMETER
            ; jbe BYTE =>within_budget
            ;; self.exit(SIG_EXCEEDED_MAX_INSTRUCTIONS)
            ; =>within_budget
        );
    }
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
    /// `reloc_add_insn_off32` relocation.
    ///
    /// The JIT holds a pointer to the second instruction of the eBPF program in `insn`,
    /// whereas the templates default to addressing where `insn` is updated to point to right
    /// after the current instruction. This relocation adds the offset of the current instruction
    /// to the field.
    InsnOffset,
    /// `template_taken_branch` relocation.
    ///
    /// When BPF instruction represents a branch, and the branch is taken, the control flow has to
    /// transfer to the machine code representing the target BPF instruction's code. Offset to this
    /// machine code is what this relocation must overwrite based on the BPF instruction being
    /// templated.
    TakenBranch,
    /// `template_taken_branch_cu_adjustment` relocation.
    ///
    /// Offset (in bytes) from the instruction following the branch to the branch target.
    TakenBranchMeterAdjustment,
    /// `template_internal_call` relocation.
    ///
    /// Same as `TakenBranch`, but for the target of an internal call (`next + imm`.)
    InternalCall,
    /// `template_internal_call_cu_adjustment` relocation.
    ///
    /// Offset (in bytes) from the instruction following the call to the call target.
    InternalCallMeterAdjustment,
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

struct JITGenerator {
    template: super::Template<128, TemplateRelocation>,
    op: u8,
    dst: u8,
    src: u8,
    /// Temporary relocations within the code that will be resolved before the template is
    /// finalized.
    ///
    /// Template can have further relocations after finalization, however those relocations may only
    /// be specific to the eBPF instruction being instantiated.
    relocs: LabelRelocs,
}

impl JITGenerator {
    pub fn new() -> Self {
        Self {
            template: super::Template::new(),
            op: 0,
            dst: 0,
            src: 0,
            relocs: LabelRelocs::new(),
        }
    }

    /// Resolve all the relocations that can be resolved without knowing the specific eBPF
    /// instruction and return the template. The generator is reset to generate the next template.
    fn finalize(&mut self) -> Template<128, TemplateRelocation> {
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
            "template_internal_call" => TemplateRelocationKind::InternalCall,
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

    fn bpf_taken_branch(&mut self) {
        x64asm!(self
            ; add RMETER, DWORD 0
            ;; self.template_reloc(TemplateRelocationKind::TakenBranchMeterAdjustment, 0, 4, 0)
            ; jmp ->template_taken_branch
        );
    }

    fn bpf_internal_call(&mut self) {
        x64asm!(self
            ; add RMETER, DWORD 0
            ;; self.template_reloc(TemplateRelocationKind::InternalCallMeterAdjustment, 0, 4, 0)
            ; call ->template_internal_call
        );
    }
}

// TODO: when dynasm supports const codegen, we can make these be generated at compile time into an
// array.
pub(super) static JIT_TEMPLATES: LazyLock<Vec<super::Template<128, TemplateRelocation>>> =
    LazyLock::new(|| {
        let mut result = Vec::with_capacity(0x10000);
        let mut generator = JITGenerator::new();
        for bpf_src in 0..16 {
            for bpf_dst in 0..16 {
                for bpf_op in 0..=u8::MAX {
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
    assert!(bpf.len() % ebpf::INSN_SIZE == 0);
    let program: &[u64] = unsafe { bpf.align_to::<u64>().1 };
    let mut pc_section = Vec::<usize>::with_capacity(program.len());
    let mut position: usize = 0;
    // first scan
    for insn in program {
        let template = &templates[*insn as u16 as usize];
        pc_section.push(position);
        position += template.offset();
    }

    let mut text_section = Vec::<u8>::with_capacity(position);
    // 2nd scan
    for (pc, insn) in program.iter().enumerate() {
        let template = &templates[*insn as u16 as usize];
        let template_start = text_section.len();
        text_section.extend_from_slice(template.buffer());
        for relocation in template.relocations() {
            let target = match relocation.kind {
                TemplateRelocationKind::InsnOffset => pc * ebpf::INSN_SIZE,
                TemplateRelocationKind::TakenBranchMeterAdjustment => {
                    let off = (*insn >> 16) as i16;
                    (off as isize * ebpf::INSN_SIZE as isize) as usize
                }
                TemplateRelocationKind::TakenBranch => {
                    let off = (*insn >> 16) as i16;
                    let target_pc = (pc as isize)
                        .checked_add(1 + off as isize)
                        .and_then(|target_pc| usize::try_from(target_pc).ok());
                    // FIXME: the verifier should have rejected these.
                    *target_pc
                        .and_then(|target_pc| pc_section.get(target_pc))
                        .expect("branch target out of bounds")
                }
                TemplateRelocationKind::InternalCallMeterAdjustment => {
                    let imm = (*insn >> 32) as i32;
                    (imm as isize * ebpf::INSN_SIZE as isize) as usize
                }
                TemplateRelocationKind::InternalCall => {
                    let imm = (*insn >> 32) as i32;
                    let target_pc = (pc as isize)
                        .checked_add(1 + imm as isize)
                        .and_then(|target_pc| usize::try_from(target_pc).ok());
                    // FIXME: the verifier should have rejected these.
                    *target_pc
                        .and_then(|target_pc| pc_section.get(target_pc))
                        .expect("call target out of bounds")
                }
            };
            relocation.apply(&mut text_section, template_start, target);
        }
    }
    text_section
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
    interpreter: Interpreter,
    relocs: LabelRelocs,
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
            let this = Self {
                interpreter: Interpreter {
                    buffer: buffer.cast(),
                },
                relocs: LabelRelocs::new(),
                offset: 0,
                op: 0,
                dst: 0,
                src: 0,
                terminal: false,
            };
            this
        }
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
        let len = (alignment - self.offset % alignment) % alignment;
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

    fn bpf_taken_branch(&mut self) {
        x64asm!(self
            ; movsx RTEMP, WORD REL32_OFF
            ; lea RMETER, [ RMETER + RTEMP*8 ]
            ; lea RINSN, [ RINSN + RTEMP*8 ]
        );
        self.terminal = true;
    }

    fn bpf_internal_call(&mut self) {
        let base_addr = i32::try_from(self.interpreter.buffer as usize).unwrap();
        x64asm!(self
            ; movsxd RTEMP, DWORD REL32_IMM
            ; lea RMETER, [ RMETER + RTEMP*8 ]
            ; lea RINSN, [ RINSN + RTEMP*8 ]
            ; movzx WTEMP, WORD [ RINSN ]
            ; shl WTEMP, InterpreterGenerator::STEP_SIZE_LOG2 as i8
            ; add WTEMP, DWORD base_addr
            ; add RINSN, 8
            ; call RTEMP
        );
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
                let step_start = generator.offset;
                generator.bpf_insn_template();
                generator.terminal = false;
                x64asm!(generator
                    ; movzx RTEMP, WORD [ RINSN ]
                    ; shl RTEMP, InterpreterGenerator::STEP_SIZE_LOG2 as i8
                    ; lea RTEMP, [ DWORD base_addr + RTEMP ]
                    ; add RINSN, 8
                    ; jmp RTEMP
                );
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
        std::slice::from_raw_parts_mut(
            generator.interpreter.buffer,
            InterpreterGenerator::STEPS_SIZE,
        )
    };
    generator.relocs.resolve(buffer, Some(base_addr as usize));

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
pub fn interpret(bpf: &[u8], meter: &mut u64) {
    let first_opcode = u16::from_le_bytes(<[u8; 2]>::try_from(&bpf[0..2]).unwrap()) as usize;
    let address = unsafe {
        INTERPRETER
            .buffer
            .add(first_opcode << InterpreterGenerator::STEP_SIZE_LOG2)
    };
    let retcode = enter(bpf, address as usize, meter);
    if retcode == SIG_EXCEEDED_MAX_INSTRUCTIONS as i64 {
        *meter = 0;
    }
}

#[unsafe(naked)]
// FIXME: pass bpf as a pointer instead
///
/// `meter` holds the instruction budget, the remaining budget is written back to it once the
/// execution terminates.
pub extern "sysv64" fn enter(bpf: &[u8], start_addr: usize, meter: &mut u64) -> i64 {
    // This function is meant to only do the bare minimum setup for the runtime to operate.
    // e.g. it will setup the VM pointer, stash the registers and setup rbp, but it won't e.g. deal
    // with writing the return value into the VM.
    naked_asm!(
        // TODO: only really need to save callee saved registers.
        "push rbp",
        "mov rbp, rsp",
        "sub rsp, 64",
        "mov [rbp - 16], rcx",
        "mov [rbp - 24], rbx",
        "mov [rbp - 32], r12",
        "mov [rbp - 40], r13",
        "mov [rbp - 48], r14",
        "mov [rbp - 56], r15",
        // the "longjmp" destination address for signals
        "lea    rax, [rip+0f]",
        "mov    qword ptr [rbp - 8], rax",
        // Initialize "internal" registers.
        // `meter`: number of the BPF instruction past which the execution of a basic block must
        // fail.
        "mov rax, rdx",
        "mov rcx, [rcx]",
        "lea rcx, [rdi + rcx * 8]",
        "mov rdx, rcx",
        "mov rcx, rax",
        // `insn`: address of the instruction following the first one.
        "lea rax, [rdi + 8]",
        // TODO: populate initial register values from VM
        "xor esi, esi",
        "xor edi, edi",
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
        // Exit code
        "movsx rax, cl",
        // `meter` holds the remaining budget in bytes of BPF instructions, negative if exceeded.
        // Compute back into the number of CUs.
        "sar rdx, 3",
        "xor ecx, ecx",
        "test rdx, rdx",
        "cmovs rdx, rcx",
        "mov rcx, [rbp - 16]",
        "mov [rcx], rdx",
        "mov rbx,  [rbp - 24]",
        "mov r12,  [rbp - 32]",
        "mov r13,  [rbp - 40]",
        "mov r14,  [rbp - 48]",
        "mov r15,  [rbp - 56]",
        // Done, return to the caller.
        "mov rsp, rbp",
        "pop rbp",
        "ret",
        "1:",
        "jmp rcx",
    )
}

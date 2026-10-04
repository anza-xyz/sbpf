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

    /// The SBPF version the code is generated for.
    fn version(&self) -> SBPFVersion;
    /// Of the instruction being generated.
    fn opcode(&self) -> TemplateOpcode;
    fn supports(&self) -> &SupportingCode;

    // Generate code to handle branch taken case.
    fn bpf_taken_branch(&mut self);

    /// The code generated so far checks the instruction meter.
    fn meter_checked(&mut self);
}

/// Set the flags for the comparison of the 64 bit registers (or the immediate) of the conditional
/// jump being generated.
fn compare_64<G: X64Generator + ?Sized>(out: &mut G, dst: Reg, src: Reg) {
    let op = out.opcode().op();
    let is_imm = (op & ebpf::BPF_X) != ebpf::BPF_X;
    let is_jset = (op & ebpf::BPF_ALU_OP_MASK) == ebpf::BPF_JSET;
    match (is_imm, is_jset) {
        (true, false) => x64asm!(out
            ; movsxd RTEMP, DWORD REL32_IMM
            ; cmp Rq(dst), RTEMP
        ),
        (true, true) => x64asm!(out
            ; movsxd RTEMP, DWORD REL32_IMM
            ; test Rq(dst), RTEMP
        ),
        (false, false) => x64asm!(out; cmp Rq(dst), Rq(src)),
        (false, true) => x64asm!(out; test Rq(dst), Rq(src)),
    }
}

/// Like `compare_64`, for the lower 32 bits.
fn compare_32<G: X64Generator + ?Sized>(out: &mut G, dst: Reg, src: Reg) {
    let op = out.opcode().op();
    let is_imm = (op & ebpf::BPF_X) != ebpf::BPF_X;
    let is_jset = (op & ebpf::BPF_ALU_OP_MASK) == ebpf::BPF_JSET;
    match (is_imm, is_jset) {
        (true, false) => x64asm!(out; cmp Rd(dst), DWORD REL32_IMM),
        (true, true) => x64asm!(out; test Rd(dst), DWORD REL32_IMM),
        (false, false) => x64asm!(out; cmp Rd(dst), Rd(src)),
        (false, true) => x64asm!(out; test Rd(dst), Rd(src)),
    }
}

/// Produce a template for a conditional jump, the flags of which are set by `compare`.
fn conditional_branch<G: X64Generator + ?Sized>(
    out: &mut G,
    dst: Reg,
    src: Reg,
    compare: impl FnOnce(&mut G, Reg, Reg),
) {
    let op = out.opcode().op();
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
fn invalid_insn<G: X64Generator + ?Sized>(out: &mut G) {
    load_next_insn_addr(out);
    bpf_validate_meter(out);
    terminate(out, SIG_INVALID_INSN)
}

/// Produce a template for a single (currently processed) instruction.
// FIXME: register tracing (`feature = "tracer"`) is not implemented.
fn bpf_insn_template<G: X64Generator + ?Sized>(out: &mut G) {
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
            let helper = out.supports().divide(is_div, is_alu64, dst, src);
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

        ebpf::CALL_IMM => {
            load_next_insn_addr(out);
            out.meter_checked();
            match (out.version().static_syscalls(), src.0) {
                (false, _) => x64asm!(out
                    ; push RTEMP
                    ; mov WTEMP, DWORD REL32_IMM
                    ;; invoke_support(out, out.supports().v0_call_imm.unwrap())
                    ; pop RTEMP
                ),
                // FIXME: the old JIT reports `UnsupportedInstruction` when the target is out of the
                // text section, whereas `call_internal` reports `CallOutsideTextSegment` like it
                // does for `callx`.
                (true, 1) => x64asm!(out
                    ; push RTEMP
                    ; movsxd RTEMP, DWORD REL32_IMM
                    ; lea RTEMP, [ DWORD 0i32 + RINSN + RTEMP * 8 ]
                    ;; out.template_reloc(TemplateRelocationKind::InsnOffset, 0, 4, 0)
                    ;; invoke_support(out, out.supports().call_internal)
                    ; pop RTEMP
                ),
                (true, 0) => invoke_support(out, out.supports().syscall),
                (true, _) => {
                    bpf_validate_meter(out);
                    terminate(out, SIG_INVALID_INSN)
                }
            }
        }
        ebpf::CALL_REG => {
            load_next_insn_addr(out);
            out.meter_checked();
            if !out.version().callx_uses_dst_reg() {
                // The register containing the destination is named by the immediate. We will use an
                // additional support to resolve this to a real register as the jump table inline
                // would otherwise be pretty nasty.
                x64asm!(out
                    ; push RTEMP
                    ; mov WTEMP, DWORD REL32_IMM
                    ;; invoke_support(out, out.supports().v0_callx.unwrap())
                    ; pop RTEMP
                );
            } else {
                x64asm!(out
                    ; push RTEMP
                    ; mov RTEMP, Rq(dst)
                    ; sub RTEMP, rbp => Frame[BYTE -1].text_section_host_to_vm
                    ;; invoke_support(out, out.supports().call_internal)
                    ; pop RTEMP
                );
            }
        }
        ebpf::EXIT => {
            load_next_insn_addr(out);
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
            load_next_insn_addr(out);
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
fn load_next_insn_addr<G: X64Generator + ?Sized>(out: &mut G) {
    x64asm!(out
        ; lea RTEMP, [ DWORD 0i32 + RINSN ]
        ;; out.template_reloc(TemplateRelocationKind::InsnOffset, 0, 4, 0)
    );
}

fn invoke_support<G: X64Generator + ?Sized>(out: &mut G, support_addr: *const u8) {
    let support_dword = i32::try_from(support_addr as usize).expect("supports in the first 2 GiB");
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
        ; jmp QWORD rbp => Frame[BYTE -1].exit
    );
}

/// Terminate the execution if the instruction budget has been exceeded.
///
/// `temp` must contain the address of the next BPF instruction.
fn bpf_validate_meter<G: X64Generator + ?Sized>(out: &mut G) {
    out.meter_checked();
    let within_budget = out.new_dynamic_label();
    x64asm!(out
        ; cmp RTEMP, RMETER
        ; jbe BYTE =>within_budget
        ;; terminate(out, SIG_EXCEEDED_MAX_INSTRUCTIONS)
        ; =>within_budget
    );
}

const MAX_JIT_TEMPLATE_SIZE: usize = 48;

struct JITGenerator<'a> {
    version: SBPFVersion,
    template: TemplateBuilder<'a, MAX_JIT_TEMPLATE_SIZE>,
    /// `None` for an `AuxTemplate`.
    opcode: Option<TemplateOpcode>,
    /// Temporary relocations within the code that will be resolved before the template is
    /// finalized.
    ///
    /// Template can have further relocations after finalization, however those relocations may only
    /// be specific to the eBPF instruction being instantiated.
    relocs: LabelRelocs<SimpleRelocation>,
    supports: &'static SupportingCode,
}

impl<'a> JITGenerator<'a> {
    fn new(
        version: SBPFVersion,
        template: TemplateBuilder<'a, MAX_JIT_TEMPLATE_SIZE>,
        opcode: Option<TemplateOpcode>,
    ) -> Self {
        Self {
            version,
            template,
            opcode,
            relocs: LabelRelocs::new(),
            supports: &interpreter(version).1,
        }
    }

    /// Generator for a BPF instruction.
    fn for_insn(
        version: SBPFVersion,
        templates: &'a mut JitTemplates<MAX_JIT_TEMPLATE_SIZE>,
        opcode: TemplateOpcode,
    ) -> Self {
        let template = templates.insn_builder(opcode);
        template.layout.extra_bpf_insns = (insn_size(opcode.op()) / 8) as u8 - 1;
        Self::new(version, template, Some(opcode))
    }

    /// Resolve all the relocations that can be resolved without knowing the specific eBPF
    /// instruction.
    fn finalize(mut self) {
        self.relocs.resolve(self.template.code_mut(), None);
    }
}

impl X64Generator for JITGenerator<'_> {
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
        self.template.extend(&value.to_le_bytes());
    }

    fn push_i8(&mut self, value: i8) {
        self.template.push(value as u8);
    }

    fn global_reloc(
        &mut self,
        name: &'static str,
        target_offset: isize,
        field_offset: u8,
        ref_offset: u8,
        kind: u8,
    ) {
        let patch =
            PatchFields::<SimpleRelocation>::new(target_offset, field_offset, ref_offset, kind);
        let kind = match name {
            "template_taken_branch" => TemplateRelocationKind::TakenBranch,
            _ => panic!("global reference to an unknown symbol {}", name),
        };
        self.template
            .add_relocation(TemplateRelocation::new(kind, self.offset(), patch));
    }

    fn template_reloc(
        &mut self,
        kind: TemplateRelocationKind,
        target_offset: isize,
        field_offset: u8,
        ref_offset: u8,
    ) {
        // kind = Absolute DWord
        let patch =
            PatchFields::<SimpleRelocation>::new(target_offset, field_offset, ref_offset, 0xC2);
        self.template
            .add_relocation(TemplateRelocation::new(kind, self.offset(), patch));
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

    fn version(&self) -> SBPFVersion {
        self.version
    }

    fn opcode(&self) -> TemplateOpcode {
        self.opcode
            .expect("not generating the template for an instruction")
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

    fn meter_checked(&mut self) {
        self.template.layout.checks_meter = true;
    }
}

// TODO: when dynasm supports const codegen, we can make these be generated at compile time into an
// array.
static JIT_TEMPLATES: [LazyLock<JitTemplates<MAX_JIT_TEMPLATE_SIZE>>; 5] = [
    LazyLock::new(|| generate_jit_templates(SBPFVersion::V0)),
    LazyLock::new(|| panic!("dynasm for v1 unlikely to be implemented")),
    LazyLock::new(|| panic!("dynasm for v2 unlikely to be implemented")),
    LazyLock::new(|| generate_jit_templates(SBPFVersion::V3)),
    // TODO: same as v3? maybe Arc-share the v3 templates or something?
    LazyLock::new(|| generate_jit_templates(SBPFVersion::V4)),
];

/// JIT templates for the SBPF `version`.
pub fn jit_templates(version: SBPFVersion) -> &'static JitTemplates<MAX_JIT_TEMPLATE_SIZE> {
    &JIT_TEMPLATES[version as usize]
}

fn generate_jit_templates(version: SBPFVersion) -> JitTemplates<MAX_JIT_TEMPLATE_SIZE> {
    type Templates = JitTemplates<MAX_JIT_TEMPLATE_SIZE>;
    let mut templates = Templates::empty();
    for opcode in TemplateOpcode::all() {
        let mut generator = JITGenerator::for_insn(version, &mut templates, opcode);
        bpf_insn_template(&mut generator);
        generator.finalize();
    }
    let generate = |templates: &mut Templates, template, f: fn(&mut JITGenerator)| {
        let mut generator = JITGenerator::new(version, templates.aux_builder(template), None);
        f(&mut generator);
        generator.finalize();
    };
    generate(&mut templates, AuxTemplate::ExecutionOverrun, |generator| {
        load_next_insn_addr(generator);
        // Running out of budget takes precedence, as in `Interpreter::step`.
        bpf_validate_meter(generator);
        terminate(generator, SIG_EXECUTION_OVERRUN);
    });
    generate(
        &mut templates,
        AuxTemplate::InvalidJumpTarget,
        |generator| {
            // Reached through `callx` only (the verifier rejects the jumps), which leaves in
            // `temp` the address of the instruction following the target, as
            // `load_next_insn_addr` would.
            bpf_validate_meter(generator);
            terminate(generator, SIG_INVALID_INSN);
        },
    );
    generate(
        &mut templates,
        AuxTemplate::Noop,
        |generator| x64asm!(generator; nop),
    );
    generate(&mut templates, AuxTemplate::MeterCheckpoint, |generator| {
        load_next_insn_addr(generator);
        bpf_validate_meter(generator);
    });
    templates
}

/// The interpreter step for the instructions with `opcode`, of the interpreter for the SBPF
/// `version`.
fn interpreter_step(version: SBPFVersion, opcode: TemplateOpcode) -> *const u8 {
    let offset = InterpreterGenerator::step_offset(opcode);
    unsafe { interpreter(version).0.buffer.add(offset) }
}

pub struct Interpreter {
    buffer: *mut u8,
}

unsafe impl Send for Interpreter {}
unsafe impl Sync for Interpreter {}

impl Drop for Interpreter {
    fn drop(&mut self) {
        unsafe { maps::unmap(self.buffer, InterpreterGenerator::STEPS_SIZE) }
    }
}

/// Memory for the interpreter, which is addressed with absolute 32-bit addresses, so it has to be
/// within the first 2 GiB of the address space.
#[cfg(target_os = "linux")]
mod maps {
    /// Read-write, until `make_exec`. With `codegen_debug`, backed by the file `interpreter-{name}.bin`
    /// to inspect.
    pub(super) unsafe fn map(len: usize, name: &str) -> *mut u8 {
        #[cfg(not(feature = "codegen_debug"))]
        let _ = name;
        #[cfg(feature = "codegen_debug")]
        let file = {
            let file = std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .create(true)
                .truncate(true)
                .open(format!("interpreter-{name}.bin"))
                .unwrap();
            file.set_len(len as u64).unwrap();
            file
        };
        #[cfg(feature = "codegen_debug")]
        let (flags, fd) = (libc::MAP_SHARED, std::os::fd::AsRawFd::as_raw_fd(&file));
        #[cfg(not(feature = "codegen_debug"))]
        let (flags, fd) = (libc::MAP_PRIVATE | libc::MAP_ANONYMOUS, -1);
        let buffer = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                len,
                libc::PROT_READ | libc::PROT_WRITE,
                flags | libc::MAP_32BIT,
                fd,
                0,
            )
        };
        if buffer == libc::MAP_FAILED {
            panic!("libc::mmap failed to allocate executable memory for the interpreter");
        }
        buffer.cast()
    }

    pub(super) unsafe fn make_exec(buffer: *mut u8, len: usize) {
        unsafe { libc::mprotect(buffer.cast(), len, libc::PROT_READ | libc::PROT_EXEC) };
    }

    pub(super) unsafe fn unmap(buffer: *mut u8, len: usize) {
        unsafe { libc::munmap(buffer.cast(), len) };
    }
}

// TODO: e.g. `VirtualAlloc` with an address hint on Windows.
#[cfg(not(target_os = "linux"))]
mod maps {
    pub(super) unsafe fn map(_len: usize, _name: &str) -> *mut u8 {
        unimplemented!("allocating memory within the first 2 GiB on this OS")
    }

    pub(super) unsafe fn make_exec(_buffer: *mut u8, _len: usize) {
        unreachable!()
    }

    pub(super) unsafe fn unmap(_buffer: *mut u8, _len: usize) {
        unreachable!()
    }
}

/// Generate an interpreter...
struct InterpreterGenerator {
    buffer: *mut u8,
    relocs: LabelRelocs<SimpleRelocation>,
    supports: SupportingCode,
    offset: usize,
    version: SBPFVersion,
    /// Of the step being generated.
    opcode: TemplateOpcode,
    /// Is the code generated for this instruction terminal?
    ///
    /// No further instructions other than the epilogue expected to appear after this point.
    terminal: bool,
}

impl InterpreterGenerator {
    const STEP_SIZE_LOG2: u8 = 7; // 128 bytes
    const STEP_TABLE_SIZE: usize = 0x1_0000 * (1 << Self::STEP_SIZE_LOG2);
    const STEPS_SIZE: usize = Self::STEP_TABLE_SIZE + SupportingCode::LEN;

    /// Offset into the `buffer` for this opcode.
    fn step_offset(opcode: TemplateOpcode) -> usize {
        opcode.index() << Self::STEP_SIZE_LOG2
    }

    fn new(version: SBPFVersion) -> Self {
        unsafe {
            let buffer = maps::map(Self::STEPS_SIZE, &format!("{:?}", version));
            let mut this = Self {
                version,
                buffer,
                relocs: LabelRelocs::new(),
                offset: 0,
                opcode: TemplateOpcode(0),
                terminal: false,
                supports: SupportingCode {
                    call_internal: std::ptr::null(),
                    syscall: std::ptr::null(),
                    v0_call_imm: None,
                    v0_callx: None,
                    memory_access: [[std::ptr::null(); 4]; 3],
                    entry_point: std::ptr::null(),
                    divide: [[[std::ptr::null(); Reg::COUNT]; Reg::COUNT]; 4],
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

    fn version(&self) -> SBPFVersion {
        self.version
    }

    fn opcode(&self) -> TemplateOpcode {
        self.opcode
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

    fn meter_checked(&mut self) { /* every step checks the meter */
    }
}

static INTERPRETERS: [LazyLock<(Interpreter, SupportingCode)>; 5] = [
    LazyLock::new(|| generate_interpreter(SBPFVersion::V0)),
    LazyLock::new(|| panic!("dynasm for v1 unlikely to be implemented")),
    LazyLock::new(|| panic!("dynasm for v2 unlikely to be implemented")),
    LazyLock::new(|| generate_interpreter(SBPFVersion::V3)),
    LazyLock::new(|| generate_interpreter(SBPFVersion::V4)),
];

/// The interpreter and the supporting code for the SBPF `version`.
fn interpreter(version: SBPFVersion) -> &'static (Interpreter, SupportingCode) {
    &INTERPRETERS[version as usize]
}

fn generate_interpreter(version: SBPFVersion) -> (Interpreter, SupportingCode) {
    let mut generator = InterpreterGenerator::new(version);
    let base_addr = i32::try_from(generator.buffer as usize).expect("interpreter in first 2GB");
    for opcode in TemplateOpcode::all() {
        let step_start = InterpreterGenerator::step_offset(opcode);
        generator.opcode = opcode;
        generator.offset = step_start;
        bpf_insn_template(&mut generator);
        generator.terminal = false;
        // `insn` points at the last 8 bytes of the instruction just executed.
        let size = i8::try_from(insn_size(opcode.op())).unwrap();
        let next_insn = if size == 8 {
            RINSN
        } else {
            x64asm!(generator; lea RTEMP, [ BYTE (size - 8) + RINSN ]);
            RTEMP
        };
        // Before dispatching the next instruction, check what the JIT does with the meter
        // checkpoints and the `execution_overrun` template, in the order of `Interpreter::step`.
        // `meter` and the limit are both the end of the last instruction that may be executed.
        let (exceeded, overrun) = (generator.new_dynamic_label(), generator.new_dynamic_label());
        x64asm!(generator
            ; cmp Rq(next_insn), RMETER
            ; jae BYTE =>exceeded
            ; cmp Rq(next_insn), rbp => Frame[BYTE -1].text_section_limit
            ; jae BYTE =>overrun
            ; movzx RTEMP, WORD [ BYTE (size - 8) + RINSN ]
            ; shl RTEMP, InterpreterGenerator::STEP_SIZE_LOG2 as i8
            ; lea RTEMP, [ DWORD base_addr + RTEMP ]
            ; add RINSN, size as i32
            ; jmp RTEMP
            ; =>exceeded
            ;; terminate(&mut generator, SIG_EXCEEDED_MAX_INSTRUCTIONS)
            ; =>overrun
            ; lea RTEMP, [ BYTE size + RINSN ]
            ;; terminate(&mut generator, SIG_EXECUTION_OVERRUN)
        );
        assert!(
            generator.offset - step_start <= 1 << InterpreterGenerator::STEP_SIZE_LOG2,
            "step for {:#x} is too long",
            opcode.0
        );
    }

    let buffer = unsafe {
        std::slice::from_raw_parts_mut(generator.buffer, InterpreterGenerator::STEPS_SIZE)
    };
    generator.relocs.resolve(buffer, Some(base_addr as usize));

    #[cfg(all(feature = "codegen_debug", target_os = "linux"))]
    // EM_X86_64
    super::write_perf_jitdump(
        &format!("interpreter {:?}", version),
        generator.buffer,
        InterpreterGenerator::STEPS_SIZE,
        62,
    );
    unsafe { maps::make_exec(generator.buffer, InterpreterGenerator::STEPS_SIZE) };
    (
        Interpreter {
            buffer: generator.buffer,
        },
        generator.supports,
    )
}

/// The state of an execution. `SupportingCode::entry_point` copies it right below its frame
/// pointer, where the generated code finds it as `rbp => Frame[BYTE -1].field`.
#[repr(C, align(16))]
struct Frame {
    /// The `EbpfVm` being executed.
    vm: *mut u8,
    /// Where `terminate` jumps to. Set up by `SupportingCode::entry_point`.
    exit: *const u8,
    /// The machine code to start executing at.
    start: usize,
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
    /// For the JIT output: the machine code being executed.
    jit_text_section: *const u8,
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
pub fn enter<C: crate::vm::ContextObject>(
    executable: &Executable<C>,
    jit: Option<(&[u32], *const u8)>,
    vm: &mut crate::vm::EbpfVm<C>,
) {
    let version = executable.get_sbpf_version();
    let (bpf_vm_addr, bpf) = executable.get_text_bytes();
    let pc = vm.registers[11] as usize;
    let (start_addr, insn, jit_pc_section, jit_text_section) = match jit {
        Some((pc_section, text_section)) => (
            text_section as usize + pc_section[pc] as usize,
            bpf.as_ptr().wrapping_add(ebpf::INSN_SIZE),
            pc_section.as_ptr(),
            text_section,
        ),
        None => {
            let starting_insn = bpf.as_chunks::<{ ebpf::INSN_SIZE }>().0[pc];
            let opcode = TemplateOpcode::of(u64::from_le_bytes(starting_insn));
            (
                interpreter_step(version, opcode) as usize,
                bpf.as_ptr().wrapping_add((pc + 1) * ebpf::INSN_SIZE),
                std::ptr::null(),
                std::ptr::null(),
            )
        }
    };
    let entry_point = interpreter(version).1.entry_point;
    let config = executable.get_config();
    assert!(
        config.enable_instruction_meter,
        "the instruction meter cannot be disabled"
    );
    let meter = initial_meter(bpf, vm);
    let (max_call_depth, stack_frame_size) = (config.max_call_depth, config.stack_frame_size);
    let gaps = version.stack_frame_gaps() && config.enable_stack_frame_gaps;
    let frames_per_call = 1 + gaps as u64;
    let mut frame = Frame {
        vm: std::ptr::from_mut(vm).cast(),
        exit: std::ptr::null(),
        start: start_addr,
        text_section: bpf.as_ptr(),
        text_section_len: bpf.len() as u64,
        text_section_limit: bpf.as_ptr_range().end,
        text_section_host_to_vm: bpf_vm_addr.wrapping_sub(bpf.as_ptr() as u64),
        jit_pc_section,
        jit_text_section,
        call_dispatcher: supporting_code::call_dispatcher::<C>(version),
        function_registry: std::ptr::from_ref(executable.get_function_registry()).cast(),
        calls_remaining: max_call_depth as u64,
        stack_frame_bump: stack_frame_size as u64 * frames_per_call,
    };
    let code: u64;
    let remaining: u64;
    unsafe {
        std::arch::asm!(
            "push rbx",
            "call r8",
            "pop rbx",
            inout("rsi") &raw mut frame => _,
            inout("r8") entry_point => _,
            inout("rax") insn => _,
            lateout("rcx") code,
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

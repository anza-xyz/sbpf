#![allow(dead_code)]
// based on: https://sourceware.org/binutils/docs/as/BPF-Opcodes.html

use std::num::NonZeroI32;

use solana_sbpf::insn_builder::{Arch, BpfCode, Cond, Endian, Instruction, MemSize, Move, Pqr, PqrOp, Source};

#[derive(arbitrary::Arbitrary, Debug, Eq, PartialEq, Copy, Clone)]
pub struct Register(u8);

impl Register {
    #[cfg(feature = "only-verified")]
    fn to_dst(&self) -> u8 {
        self.0 % 10 // cannot write to r10
    }

    #[cfg(not(feature = "only-verified"))]
    fn to_dst(&self) -> u8 {
        self.0 % 11 // cannot write to r10, but we'll try anyways
    }

    fn to_src(&self) -> u8 {
        self.0 % 11
    }
}

#[derive(arbitrary::Arbitrary, Debug, Eq, PartialEq, Copy, Clone)]
pub enum FuzzedSource {
    Reg(Register),
    Imm(i32),
}

#[derive(arbitrary::Arbitrary, Debug, Eq, PartialEq, Copy, Clone)]
pub enum FuzzedNonZeroSource {
    Reg(Register),
    Imm(NonZeroI32),
}

impl From<&FuzzedSource> for Source {
    fn from(src: &FuzzedSource) -> Self {
        match src {
            FuzzedSource::Reg(_) => Source::Reg,
            FuzzedSource::Imm(_) => Source::Imm,
        }
    }
}

impl From<&FuzzedNonZeroSource> for Source {
    fn from(src: &FuzzedNonZeroSource) -> Self {
        match src {
            FuzzedNonZeroSource::Reg(_) => Source::Reg,
            FuzzedNonZeroSource::Imm(_) => Source::Imm,
        }
    }
}

#[derive(arbitrary::Arbitrary, Debug, Eq, PartialEq, Copy, Clone)]
pub enum SwapSize {
    S16 = 16,
    S32 = 32,
    S64 = 64,
}

#[derive(arbitrary::Arbitrary, Debug, Eq, PartialEq, Copy, Clone)]
pub enum FuzzedInstruction {
    Add(Arch, Register, FuzzedSource),
    Sub(Arch, Register, FuzzedSource),
    Mul(Arch, Register, FuzzedSource),
    Div(Arch, Register, FuzzedNonZeroSource),
    BitOr(Arch, Register, FuzzedSource),
    BitAnd(Arch, Register, FuzzedSource),
    LeftShift(Arch, Register, FuzzedSource),
    RightShift(Arch, Register, FuzzedSource),
    Negate(Arch, Register),
    Modulo(Arch, Register, FuzzedNonZeroSource),
    BitXor(Arch, Register, FuzzedSource),
    Mov(Arch, Register, FuzzedSource),
    SRS(Arch, Register, FuzzedSource),
    SwapBytes(Register, Endian, SwapSize),
    #[cfg(feature = "only-verified")]
    // load only has lddw; there are no other variants, and it needs to be split
    Load(Register, i32, i32),
    #[cfg(not(feature = "only-verified"))]
    // illegal load variants
    #[cfg(not(feature = "only-verified"))]
    Load(Register, MemSize, i64),
    #[cfg(not(feature = "only-verified"))]
    LoadAbs(MemSize, i32),
    #[cfg(not(feature = "only-verified"))]
    LoadInd(MemSize, Register, i32),
    #[cfg(not(feature = "only-verified"))]
    LoadX(Register, MemSize, Register, i16),
    Store(Register, MemSize, i16, i32),
    StoreX(Register, MemSize, i16, Register),
    Jump(i16),
    JumpC(Register, Cond, FuzzedSource, i16),
    Call(FuzzedSource),
    Exit,
    // PQR instructions for SBPF V2 (when enable_pqr() is true)
    Pqr(PqrOp, Arch, Register, FuzzedNonZeroSource),
    // JMP32 instructions for SBPF V3+ (when enable_jmp32() is true)
    JumpC32(Register, Cond, FuzzedSource, i16),
    // HOR64_IMM instruction for SBPF V2 (when disable_lddw() is true)
    Hor64Imm(Register, i32),
    // Stack frame adjustment (ADD64_IMM to r10) for V1+ when manual_stack_frame_bump() is true
    // The immediate must be aligned to 64 bytes
    #[cfg(feature = "only-verified")]
    StackAdjust(i16), // i16 to keep it small, will be multiplied by 64 for alignment
}

pub type FuzzProgram = Vec<FuzzedInstruction>;

fn complete_alu_insn<'i>(insn: Move<'i>, dst: &Register, src: &FuzzedSource) {
    match src {
        FuzzedSource::Reg(r) => insn.set_dst(dst.to_dst()).set_src(r.to_src()).push(),
        FuzzedSource::Imm(imm) => insn.set_dst(dst.to_dst()).set_imm(*imm as i64).push(),
    };
}

fn complete_alu_insn_shift<'i>(insn: Move<'i>, dst: &Register, src: &FuzzedSource, max: i64) {
    match src {
        FuzzedSource::Reg(r) => insn.set_dst(dst.to_dst()).set_src(r.to_src()).push(),
        FuzzedSource::Imm(imm) => insn
            .set_dst(dst.to_dst())
            .set_imm((*imm as i64).rem_euclid(max))
            .push(),
    };
}

fn complete_alu_insn_nonzero<'i>(insn: Move<'i>, dst: &Register, src: &FuzzedNonZeroSource) {
    match src {
        FuzzedNonZeroSource::Reg(r) => insn.set_dst(dst.to_dst()).set_src(r.to_src()).push(),
        FuzzedNonZeroSource::Imm(imm) => insn
            .set_dst(dst.to_dst())
            .set_imm(i32::from(*imm) as i64)
            .push(),
    };
}

fn complete_pqr_insn<'i>(insn: Pqr<'i>, dst: &Register, src: &FuzzedNonZeroSource) {
    match src {
        FuzzedNonZeroSource::Reg(r) => insn.set_dst(dst.to_dst()).set_src(r.to_src()).push(),
        FuzzedNonZeroSource::Imm(imm) => insn
            .set_dst(dst.to_dst())
            .set_imm(i32::from(*imm) as i64)
            .push(),
    };
}

/// Determines if an instruction should be skipped for a given SBPF version
fn should_skip_instruction(insn: &FuzzedInstruction, sbpf_version: solana_sbpf::program::SBPFVersion) -> bool {
    match insn {
        // MUL, DIV, MOD are not valid in V2+ (they use PQR instructions instead)
        FuzzedInstruction::Mul(_, _, _)
        | FuzzedInstruction::Div(_, _, _)
        | FuzzedInstruction::Modulo(_, _, _) if sbpf_version.enable_pqr() => true,
        // PQR instructions are only valid in V2+
        FuzzedInstruction::Pqr(_, _, _, _) if !sbpf_version.enable_pqr() => true,
        // UHMUL and SHMUL are not supported for 32-bit
        #[cfg(feature = "only-verified")]
        FuzzedInstruction::Pqr(op, Arch::X32, _, _)
            if matches!(op, PqrOp::Uhmul | PqrOp::Shmul) => true,
        // JMP32 instructions are only valid in V3+
        FuzzedInstruction::JumpC32(_, cond, _, _) if !sbpf_version.enable_jmp32() || matches!(cond, Cond::Abs) => true,
        // HOR64_IMM is only valid when LDDW is disabled (V2)
        FuzzedInstruction::Hor64Imm(_, _) if !sbpf_version.disable_lddw() => true,
        // NEG is disabled in some versions
        FuzzedInstruction::Negate(_, _) if sbpf_version.disable_neg() => true,
        // LE (Little Endian) is disabled in V2
        FuzzedInstruction::SwapBytes(_, Endian::Little, _) if sbpf_version.disable_le() => true,
        // LDDW (Load Double Word) is disabled in V2
        #[cfg(feature = "only-verified")]
        FuzzedInstruction::Load(_, _, _) if sbpf_version.disable_lddw() => true,
        // StackAdjust only valid for V1+ when manual_stack_frame_bump() is true
        #[cfg(feature = "only-verified")]
        FuzzedInstruction::StackAdjust(_) if !sbpf_version.manual_stack_frame_bump() => true,
        _ => false,
    }
}

#[cfg(feature = "only-verified")]
fn fix_jump(prog: &FuzzProgram, off: i16, pos: usize, len: usize, sbpf_version: solana_sbpf::program::SBPFVersion) -> i16 {
    let target = (off as usize).rem_euclid(len);
    if target == 0 {
        return target as i16 - pos as i16 - 1;
    }
    let mut remaining = target;
    for insn in prog.iter() {
        if should_skip_instruction(insn, sbpf_version) {
            continue;
        }

        let next = match insn {
            FuzzedInstruction::Load(_, _, _) => remaining.checked_sub(2),
            _ => remaining.checked_sub(1),
        };
        match next {
            None => {
                return target as i16 - pos as i16 - 2;
            }
            Some(0) => {
                return target as i16 - pos as i16 - 1;
            }
            Some(next) => remaining = next,
        }
    }
    unreachable!("Incorrectly computed length.")
}

#[cfg(not(feature = "only-verified"))]
fn fix_jump(_: &FuzzProgram, off: i16, _: usize, _: usize, _: solana_sbpf::program::SBPFVersion) -> i16 {
    off
}

// lddw is twice length; also account for skipped instructions based on version
fn calculate_length(prog: &FuzzProgram, sbpf_version: solana_sbpf::program::SBPFVersion) -> usize {
    prog.iter().map(|insn| {
        if should_skip_instruction(insn, sbpf_version) {
            0
        } else {
            // LDDW instructions take 2 slots
            #[cfg(feature = "only-verified")]
            if matches!(insn, FuzzedInstruction::Load(_, _, _)) {
                return 2;
            }
            1
        }
    }).sum()
}

pub fn make_program(prog: &FuzzProgram, sbpf_version: solana_sbpf::program::SBPFVersion) -> BpfCode {
    let mut code = BpfCode::new(sbpf_version);
    let len = calculate_length(prog, sbpf_version);
    let mut pos = 0;
    for inst in prog.iter() {
        let op = match inst {
            FuzzedInstruction::JumpC(_, Cond::Abs, FuzzedSource::Reg(_), off) => {
                FuzzedInstruction::Jump(*off)
            }
            _ => *inst,
        };

        // Skip instructions that are not valid for this SBPF version
        if should_skip_instruction(&op, sbpf_version) {
            continue;
        }

        match &op {
            FuzzedInstruction::Add(a, d, s) => complete_alu_insn(code.add(s.into(), *a), d, s),
            FuzzedInstruction::Sub(a, d, s) => complete_alu_insn(code.sub(s.into(), *a), d, s),
            FuzzedInstruction::Mul(a, d, s) => complete_alu_insn(code.mul(s.into(), *a), d, s),
            FuzzedInstruction::Div(a, d, s) => {
                complete_alu_insn_nonzero(code.div(s.into(), *a), d, s)
            }
            FuzzedInstruction::BitOr(a, d, s) => complete_alu_insn(code.bit_or(s.into(), *a), d, s),
            FuzzedInstruction::BitAnd(a, d, s) => {
                complete_alu_insn(code.bit_and(s.into(), *a), d, s)
            }
            FuzzedInstruction::LeftShift(a, d, s) => match a {
                Arch::X64 => complete_alu_insn_shift(code.left_shift(s.into(), *a), d, s, 64),
                Arch::X32 => complete_alu_insn_shift(code.left_shift(s.into(), *a), d, s, 32),
            },
            FuzzedInstruction::RightShift(a, d, s) => match a {
                Arch::X64 => complete_alu_insn_shift(code.right_shift(s.into(), *a), d, s, 64),
                Arch::X32 => complete_alu_insn_shift(code.right_shift(s.into(), *a), d, s, 32),
            },
            FuzzedInstruction::Negate(a, d) => {
                code.negate(*a).set_dst(d.to_dst()).push();
            }
            FuzzedInstruction::Modulo(a, d, s) => {
                complete_alu_insn_nonzero(code.modulo(s.into(), *a), d, s)
            }
            FuzzedInstruction::BitXor(a, d, s) => {
                complete_alu_insn(code.bit_xor(s.into(), *a), d, s)
            }
            FuzzedInstruction::Mov(a, d, s) => complete_alu_insn(code.mov(s.into(), *a), d, s),
            FuzzedInstruction::SRS(a, d, s) => match a {
                Arch::X64 => {
                    complete_alu_insn_shift(code.signed_right_shift(s.into(), *a), d, s, 64)
                }
                Arch::X32 => {
                    complete_alu_insn_shift(code.signed_right_shift(s.into(), *a), d, s, 32)
                }
            },
            FuzzedInstruction::SwapBytes(d, e, s) => {
                code.swap_bytes(*e)
                    .set_dst(d.to_dst())
                    .set_imm(*s as i64)
                    .push();
            }
            #[cfg(feature = "only-verified")]
            FuzzedInstruction::Load(d, imm1, imm2) => {
                // lddw is split in two
                code.load(MemSize::DoubleWord)
                    .set_dst(d.to_dst())
                    .set_imm(*imm1 as i64)
                    .push()
                    .load(MemSize::Word)
                    .set_imm(*imm2 as i64)
                    .push();
                pos += 1;
            }
            #[cfg(not(feature = "only-verified"))]
            FuzzedInstruction::Load(d, m, imm) => {
                // For testing: generate potentially invalid/malformed LDDW variants
                // (not split into two instructions as required by spec)
                code.load(*m).set_dst(d.to_dst()).set_imm(*imm).push();
            }
            #[cfg(not(feature = "only-verified"))]
            FuzzedInstruction::LoadAbs(m, imm) => {
                code.load_abs(*m).set_imm(*imm as i64).push();
            }
            #[cfg(not(feature = "only-verified"))]
            FuzzedInstruction::LoadInd(m, s, imm) => {
                code.load_ind(*m)
                .set_src(s.to_src())
                .set_imm(*imm as i64)
                .push();
            }
            #[cfg(not(feature = "only-verified"))]
            FuzzedInstruction::LoadX(d, m, s, off) => {
                // Automatically uses V2 encoding when move_memory_instruction_classes() is true
                code.load_x(*m)
                    .set_dst(d.to_dst())
                    .set_src(s.to_src())
                    .set_off(*off)
                    .push();
            }
            FuzzedInstruction::Store(d, m, off, imm) => {
                // Automatically uses V2 encoding when move_memory_instruction_classes() is true
                code.store(*m)
                    .set_dst(d.to_dst())
                    .set_off(*off)
                    .set_imm(*imm as i64)
                    .push();
            }
            FuzzedInstruction::StoreX(d, m, off, s) => {
                // Automatically uses V2 encoding when move_memory_instruction_classes() is true
                code.store_x(*m)
                    .set_dst(d.to_dst())
                    .set_off(*off)
                    .set_src(s.to_src())
                    .push();
            }
            FuzzedInstruction::Jump(off) => {
                code.jump_unconditional()
                    .set_off(fix_jump(&prog, *off, pos, len, sbpf_version))
                    .push();
            }
            FuzzedInstruction::JumpC(d, c, s, off) => {
                match s {
                    FuzzedSource::Reg(r) => code
                        .jump_conditional(*c, s.into())
                        .set_dst(d.to_dst())
                        .set_src(r.to_src())
                        .set_off(fix_jump(&prog, *off, pos, len, sbpf_version))
                        .push(),
                    FuzzedSource::Imm(imm) => code
                        .jump_conditional(*c, s.into())
                        .set_dst(d.to_dst())
                        .set_imm(*imm as i64)
                        .set_off(fix_jump(&prog, *off, pos, len, sbpf_version))
                        .push(),
                };
            }
            FuzzedInstruction::Call(src) => {
                match src {
                    FuzzedSource::Imm(imm) => {
                        code.call().set_imm(*imm as i64).push();
                    }
                    FuzzedSource::Reg(r) => {
                        // CALL_REG (callx) - automatically handles version-specific register encoding
                        // Registers are restricted to 0-9 (not 10), so we use to_dst()
                        let reg = r.to_dst();
                        code.call_reg()
                            .set_dst(reg)
                            .set_src(reg)
                            .set_imm(reg as i64)
                            .push();
                    }
                }
            }
            FuzzedInstruction::Pqr(pqr_op, a, d, s) => {
                complete_pqr_insn(code.pqr(s.into(), *a, *pqr_op), d, s)
            }
            FuzzedInstruction::JumpC32(d, c, s, off) => {
                match s {
                    FuzzedSource::Reg(r) => code
                        .jump_conditional_32(*c, Source::Reg)
                        .set_dst(d.to_dst())
                        .set_src(r.to_src())
                        .set_off(fix_jump(&prog, *off, pos, len, sbpf_version))
                        .push(),
                    FuzzedSource::Imm(imm) => code
                        .jump_conditional_32(*c, Source::Imm)
                        .set_dst(d.to_dst())
                        .set_imm(*imm as i64)
                        .set_off(fix_jump(&prog, *off, pos, len, sbpf_version))
                        .push(),
                };
            }
            FuzzedInstruction::Hor64Imm(d, imm) => {
                code.hor64_imm().set_dst(d.to_dst()).set_imm(*imm as i64).push();
            }
            #[cfg(feature = "only-verified")]
            FuzzedInstruction::StackAdjust(factor) => {
                // ADD64_IMM to r10 (FRAME_PTR_REG) - immediate must be aligned to 64 bytes
                use solana_sbpf::ebpf::FRAME_PTR_REG;
                code.add(Source::Imm, Arch::X64)
                    .set_dst(FRAME_PTR_REG as u8)
                    .set_imm((*factor as i64) * 64)
                    .push();
            }
            FuzzedInstruction::Exit => {
                code.exit().push();
            }
        };
        pos += 1;
    }
    code.exit().push();
    code
}

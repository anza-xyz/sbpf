#![allow(dead_code)]

use solana_sbpf::insn_builder::{Arch, BpfCode, Cond, Endian, Instruction, MemSize, PqrOp, Source};

#[derive(arbitrary::Arbitrary, Debug, Eq, PartialEq)]
pub enum FuzzedOp {
    Add(Arch, Source),
    Sub(Arch, Source),
    Mul(Arch, Source),
    Div(Arch, Source),
    BitOr(Arch, Source),
    BitAnd(Arch, Source),
    LeftShift(Arch, Source),
    RightShift(Arch, Source),
    Negate(Arch),
    Modulo(Arch, Source),
    BitXor(Arch, Source),
    Mov(Arch, Source),
    SRS(Arch, Source),
    SwapBytes(Endian),
    Load(MemSize),
    LoadAbs(MemSize),
    LoadInd(MemSize),
    LoadX(MemSize),
    Store(MemSize),
    StoreX(MemSize),
    Jump,
    JumpC(Cond, Source),
    Call,
    CallReg,
    Exit,
    // V2 instructions
    Pqr(PqrOp, Arch, Source),
    LoadV2(MemSize),
    StoreV2(MemSize),
    StoreV2X(MemSize),
    Hor64Imm,
    // V3+ instructions
    JumpC32(Cond, Source),
}

impl FuzzedOp {
    fn similarity(&self, other: &FuzzedOp) -> Option<u8> {
        if std::mem::discriminant(self) == std::mem::discriminant(&other) {
            if &self == &other {
                Some(0)
            } else {
                Some(8)
            }
        } else {
            None
        }
    }
}

#[derive(arbitrary::Arbitrary, Debug)]
pub struct FuzzedInstruction {
    pub op: FuzzedOp,
    pub dst: u8,
    pub src: u8,
    pub off: i16,
    pub imm: i64,
}

impl FuzzedInstruction {
    pub fn similarity(&self, other: &FuzzedInstruction) -> Option<u8> {
        self.op.similarity(&other.op).map(|s| {
            s + (self.dst == other.dst) as u8
                + (self.src == other.src) as u8
                + (self.off == other.off) as u8
                + (self.imm == other.imm) as u8
        })
    }
}

pub type FuzzProgram = Vec<FuzzedInstruction>;

pub fn make_program(
    prog: &FuzzProgram,
    sbpf_version: solana_sbpf::program::SBPFVersion,
) -> BpfCode {
    let mut code = BpfCode::new(sbpf_version);
    for inst in prog {
        match inst.op {
            FuzzedOp::Add(arch, src) => code
                .add(src, arch)
                .set_dst(inst.dst)
                .set_src(inst.src)
                .set_off(inst.off)
                .set_imm(inst.imm)
                .push(),
            FuzzedOp::Sub(arch, src) => code
                .sub(src, arch)
                .set_dst(inst.dst)
                .set_src(inst.src)
                .set_off(inst.off)
                .set_imm(inst.imm)
                .push(),
            FuzzedOp::Mul(arch, src) => code
                .mul(src, arch)
                .set_dst(inst.dst)
                .set_src(inst.src)
                .set_off(inst.off)
                .set_imm(inst.imm)
                .push(),
            FuzzedOp::Div(arch, src) => code
                .div(src, arch)
                .set_dst(inst.dst)
                .set_src(inst.src)
                .set_off(inst.off)
                .set_imm(inst.imm)
                .push(),
            FuzzedOp::BitOr(arch, src) => code
                .bit_or(src, arch)
                .set_dst(inst.dst)
                .set_src(inst.src)
                .set_off(inst.off)
                .set_imm(inst.imm)
                .push(),
            FuzzedOp::BitAnd(arch, src) => code
                .bit_and(src, arch)
                .set_dst(inst.dst)
                .set_src(inst.src)
                .set_off(inst.off)
                .set_imm(inst.imm)
                .push(),
            FuzzedOp::LeftShift(arch, src) => code
                .left_shift(src, arch)
                .set_dst(inst.dst)
                .set_src(inst.src)
                .set_off(inst.off)
                .set_imm(inst.imm)
                .push(),
            FuzzedOp::RightShift(arch, src) => code
                .right_shift(src, arch)
                .set_dst(inst.dst)
                .set_src(inst.src)
                .set_off(inst.off)
                .set_imm(inst.imm)
                .push(),
            FuzzedOp::Negate(arch) => code
                .negate(arch)
                .set_dst(inst.dst)
                .set_src(inst.src)
                .set_off(inst.off)
                .set_imm(inst.imm)
                .push(),
            FuzzedOp::Modulo(arch, src) => code
                .modulo(src, arch)
                .set_dst(inst.dst)
                .set_src(inst.src)
                .set_off(inst.off)
                .set_imm(inst.imm)
                .push(),
            FuzzedOp::BitXor(arch, src) => code
                .bit_xor(src, arch)
                .set_dst(inst.dst)
                .set_src(inst.src)
                .set_off(inst.off)
                .set_imm(inst.imm)
                .push(),
            FuzzedOp::Mov(arch, src) => code
                .mov(src, arch)
                .set_dst(inst.dst)
                .set_src(inst.src)
                .set_off(inst.off)
                .set_imm(inst.imm)
                .push(),
            FuzzedOp::SRS(arch, src) => code
                .signed_right_shift(src, arch)
                .set_dst(inst.dst)
                .set_src(inst.src)
                .set_off(inst.off)
                .set_imm(inst.imm)
                .push(),
            FuzzedOp::SwapBytes(endian) => code
                .swap_bytes(endian)
                .set_dst(inst.dst)
                .set_src(inst.src)
                .set_off(inst.off)
                .set_imm(inst.imm)
                .push(),
            FuzzedOp::Load(mem) => code
                .load(mem)
                .set_dst(inst.dst)
                .set_src(inst.src)
                .set_off(inst.off)
                .set_imm(inst.imm)
                .push(),
            FuzzedOp::LoadAbs(mem) => code
                .load_abs(mem)
                .set_dst(inst.dst)
                .set_src(inst.src)
                .set_off(inst.off)
                .set_imm(inst.imm)
                .push(),
            FuzzedOp::LoadInd(mem) => code
                .load_ind(mem)
                .set_dst(inst.dst)
                .set_src(inst.src)
                .set_off(inst.off)
                .set_imm(inst.imm)
                .push(),
            FuzzedOp::LoadX(mem) => code
                .load_x(mem)
                .set_dst(inst.dst)
                .set_src(inst.src)
                .set_off(inst.off)
                .set_imm(inst.imm)
                .push(),
            FuzzedOp::Store(mem) => code
                .store(mem)
                .set_dst(inst.dst)
                .set_src(inst.src)
                .set_off(inst.off)
                .set_imm(inst.imm)
                .push(),
            FuzzedOp::StoreX(mem) => code
                .store_x(mem)
                .set_dst(inst.dst)
                .set_src(inst.src)
                .set_off(inst.off)
                .set_imm(inst.imm)
                .push(),
            FuzzedOp::Jump => code
                .jump_unconditional()
                .set_dst(inst.dst)
                .set_src(inst.src)
                .set_off(inst.off)
                .set_imm(inst.imm)
                .push(),
            FuzzedOp::JumpC(cond, src) => code
                .jump_conditional(cond, src)
                .set_dst(inst.dst)
                .set_src(inst.src)
                .set_off(inst.off)
                .set_imm(inst.imm)
                .push(),
            FuzzedOp::Call => code
                .call()
                .set_dst(inst.dst)
                .set_src(inst.src)
                .set_off(inst.off)
                .set_imm(inst.imm)
                .push(),
            FuzzedOp::CallReg => code
                .call_reg()
                .set_dst(inst.dst)
                .set_src(inst.src)
                .set_off(inst.off)
                .set_imm(inst.imm)
                .push(),
            FuzzedOp::Exit => code
                .exit()
                .set_dst(inst.dst)
                .set_src(inst.src)
                .set_off(inst.off)
                .set_imm(inst.imm)
                .push(),
            // V2 instructions
            FuzzedOp::Pqr(pqr_op, arch, src) => code
                .pqr(src, arch, pqr_op)
                .set_dst(inst.dst)
                .set_src(inst.src)
                .set_off(inst.off)
                .set_imm(inst.imm)
                .push(),
            FuzzedOp::LoadV2(mem) => code
                .load_x(mem)
                .set_dst(inst.dst)
                .set_src(inst.src)
                .set_off(inst.off)
                .set_imm(inst.imm)
                .push(),
            FuzzedOp::StoreV2(mem) => code
                .store(mem)
                .set_dst(inst.dst)
                .set_src(inst.src)
                .set_off(inst.off)
                .set_imm(inst.imm)
                .push(),
            FuzzedOp::StoreV2X(mem) => code
                .store_x(mem)
                .set_dst(inst.dst)
                .set_src(inst.src)
                .set_off(inst.off)
                .set_imm(inst.imm)
                .push(),
            FuzzedOp::Hor64Imm => code
                .hor64_imm()
                .set_dst(inst.dst)
                .set_src(inst.src)
                .set_off(inst.off)
                .set_imm(inst.imm)
                .push(),
            // V3+ instructions
            FuzzedOp::JumpC32(cond, src) => code
                .jump_conditional_32(cond, src)
                .set_dst(inst.dst)
                .set_src(inst.src)
                .set_off(inst.off)
                .set_imm(inst.imm)
                .push(),
        };
    }
    code
}

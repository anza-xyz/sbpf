//! The helpers for division and remainder by a register.

use super::*;

/// The result of the division that a helper produces.
#[derive(Clone, Copy)]
pub(in crate::codegen) enum DivOp {
    Div,
    Mod,
}

/// The width of the operands of a division.
#[derive(Clone, Copy)]
pub(in crate::codegen) enum Width {
    W32,
    W64,
}

/// The helpers for `DIV*_REG` and `MOD*_REG`.
///
/// One version for each operation, width, destination and source register combo.
pub(in crate::codegen) struct DivideHelpers {
    addresses: [[[[u32; Reg::COUNT]; Reg::COUNT]; 2]; 2],
}

impl DivideHelpers {
    pub(in crate::codegen) fn get(&self, op: DivOp, width: Width, dst: Reg, src: Reg) -> u32 {
        self.addresses[op as usize][width as usize][usize::from(dst.0)][usize::from(src.0)]
    }

    pub(super) fn generate(out: &mut Asm, base: u32) -> Self {
        let mut addresses = [[[[0; Reg::COUNT]; Reg::COUNT]; 2]; 2];
        for op in [DivOp::Div, DivOp::Mod] {
            for width in [Width::W32, Width::W64] {
                let kind = &mut addresses[op as usize][width as usize];
                for dst in Reg::ALL {
                    for src in Reg::ALL {
                        kind[usize::from(dst.0)][usize::from(src.0)] = address(out, base, true);
                        Self::div_mod(out, op, width, dst, src);
                    }
                }
            }
        }
        Self { addresses }
    }

    fn div_mod(out: &mut Asm, op: DivOp, width: Width, dst: Reg, src: Reg) {
        let zero = out.new_dynamic_label();
        match width {
            Width::W64 => x64asm!(out; test Rq(src), Rq(src)),
            Width::W32 => x64asm!(out; test Rd(src), Rd(src)),
        }
        // `RINSN` is saved by `invoke_support`. `RMETER` is the only thing we have to spill here.
        x64asm!(out
            ; jz =>zero
            ; push RMETER
            ; xor edx, edx
        );
        match (width, op) {
            (Width::W64, DivOp::Div) => x64asm!(out
                ; mov rax, Rq(dst)
                ; div Rq(src)
                ; mov Rq(dst), rax
            ),
            (Width::W64, DivOp::Mod) => x64asm!(out
                ; mov rax, Rq(dst)
                ; div Rq(src)
                ; mov Rq(dst), rdx
            ),
            (Width::W32, DivOp::Div) => x64asm!(out
                ; mov eax, Rd(dst)
                ; div Rd(src)
                ; mov Rd(dst), eax
            ),
            (Width::W32, DivOp::Mod) => x64asm!(out
                ; mov eax, Rd(dst)
                ; div Rd(src)
                ; mov Rd(dst), edx
            ),
        }
        x64asm!(out
            ; pop RMETER
            ; ret
            ; =>zero
            ;; validate_meter(out)
            ;; terminate(out, SIG_DIVIDE_BY_ZERO)
        );
    }
}

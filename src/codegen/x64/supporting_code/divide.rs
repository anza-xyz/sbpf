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

/// The helpers for various division operations.
pub(in crate::codegen) struct DivideHelpers {
    /// One version for each operation, width, destination and source register combo.
    unsigned: [[[[u32; Reg::COUNT]; Reg::COUNT]; 2]; 2],
    /// One version for each operation, width, destination and source register combo.
    signed: [[[[u32; Reg::COUNT]; Reg::COUNT]; 2]; 2],
    /// One version for each operation, width and destination register combo.
    signed_imm: [[[u32; Reg::COUNT]; 2]; 2],
}

impl DivideHelpers {
    pub(in crate::codegen) fn get(&self, op: DivOp, width: Width, dst: Reg, src: Reg) -> u32 {
        self.unsigned[op as usize][width as usize][usize::from(dst.0)][usize::from(src.0)]
    }

    /// The signed division or remainder of `dst` by `src`.
    ///
    /// Terminates the execution if `src` is zero or the result overflows.
    pub(in crate::codegen) fn get_signed(
        &self,
        op: DivOp,
        width: Width,
        dst: Reg,
        src: Reg,
    ) -> u32 {
        self.signed[op as usize][width as usize][usize::from(dst.0)][usize::from(src.0)]
    }

    /// The signed division or remainder of `dst` by the immediate of the instruction preceding the
    /// address in `RTEMP`.
    ///
    /// Terminates the execution if the result overflows. The immediate is not checked for zero, as
    /// the verifier rejects that.
    pub(in crate::codegen) fn get_signed_imm(&self, op: DivOp, width: Width, dst: Reg) -> u32 {
        self.signed_imm[op as usize][width as usize][usize::from(dst.0)]
    }

    pub(super) fn generate(out: &mut Asm, base: u32) -> Self {
        let mut unsigned = [[[[0; Reg::COUNT]; Reg::COUNT]; 2]; 2];
        let mut signed = [[[[0; Reg::COUNT]; Reg::COUNT]; 2]; 2];
        let mut signed_imm = [[[0; Reg::COUNT]; 2]; 2];
        for op in [DivOp::Div, DivOp::Mod] {
            for width in [Width::W32, Width::W64] {
                let (o, w) = (op as usize, width as usize);
                for dst in Reg::ALL {
                    let d = usize::from(dst.0);
                    for src in Reg::ALL {
                        let s = usize::from(src.0);
                        unsigned[o][w][d][s] = address(out, base, true);
                        Self::div_mod(out, op, width, dst, src);
                        signed[o][w][d][s] = address(out, base, true);
                        Self::signed_div_rem(out, op, width, dst, Some(src));
                    }
                    signed_imm[o][w][d] = address(out, base, true);
                    Self::signed_div_rem(out, op, width, dst, None);
                }
            }
        }
        Self {
            unsigned,
            signed,
            signed_imm,
        }
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
            ; push rdx
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
            ; pop rdx
            ; ret
            ; =>zero
            ;; validate_meter(out)
            ;; terminate(out, SIG_DIVIDE_BY_ZERO)
        );
    }

    /// `dst s/= src` or `dst s%= src`.
    ///
    /// `src = None` requires `RTEMP` to hold address to the .
    ///
    /// Divisions by zero and `_::MIN / -1` terminate the execution.
    fn signed_div_rem(out: &mut Asm, op: DivOp, width: Width, dst: Reg, src: Option<Reg>) {
        let [zero, overflow, divide] = std::array::from_fn(|_| out.new_dynamic_label());
        if src.is_none() {
            x64asm!(out
                ; push RTEMP
                ; movsxd RTEMP, DWORD [BYTE -4 + RTEMP]
            );
        }
        match (src, width) {
            (Some(src), Width::W64) => x64asm!(out
                ; test Rq(src), Rq(src)
                ; jz =>zero
                ; cmp Rq(src), -1
                ; jne =>divide
                ; mov rax, Rq(dst)
                ; neg rax
                ; jo =>overflow
            ),
            (Some(src), Width::W32) => x64asm!(out
                ; test Rd(src), Rd(src)
                ; jz =>zero
                ; cmp Rd(src), -1
                ; jne =>divide
                ; mov eax, Rd(dst)
                ; neg eax
                ; jo =>overflow
            ),
            (None, Width::W64) => x64asm!(out
                ; cmp RTEMP, -1
                ; jne =>divide
                ; mov rax, Rq(dst)
                ; neg rax
                ; jo =>overflow
            ),
            (None, Width::W32) => x64asm!(out
                ; cmp WTEMP, -1
                ; jne =>divide
                ; mov eax, Rd(dst)
                ; neg eax
                ; jo =>overflow
            ),
        }
        // `rax` is saved by `invoke_support`, so only `rdx` needs to be saved for `idiv`.
        x64asm!(out
            ; =>divide
            ; push rdx
        );
        let divisor = src.map_or(RTEMP, u8::from);
        match width {
            Width::W64 => x64asm!(out
                ; mov rax, Rq(dst)
                ; cqo
                ; idiv Rq(divisor)
            ),
            Width::W32 => x64asm!(out
                ; mov eax, Rd(dst)
                ; cdq
                ; idiv Rd(divisor)
            ),
        }
        match (width, op) {
            (Width::W64, DivOp::Div) => x64asm!(out; mov Rq(dst), rax),
            (Width::W64, DivOp::Mod) => x64asm!(out; mov Rq(dst), rdx),
            (Width::W32, DivOp::Div) => x64asm!(out; mov Rd(dst), eax),
            (Width::W32, DivOp::Mod) => x64asm!(out; mov Rd(dst), edx),
        }
        x64asm!(out
            ; pop rdx
            ;; if src.is_none() { x64asm!(out; pop RTEMP) }
            ; ret
        );
        x64asm!(out
            ; =>overflow
            ;; if src.is_none() { x64asm!(out; pop RTEMP) }
            ;; validate_meter(out)
            ;; terminate(out, SIG_DIVIDE_OVERFLOW)
        );
        if src.is_some() {
            x64asm!(out
                ; =>zero
                ;; validate_meter(out)
                ;; terminate(out, SIG_DIVIDE_BY_ZERO)
            );
        }
    }
}

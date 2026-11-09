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

/// Generate the [`SupportEntry`]s of the divisions.
pub(super) fn generate(out: &mut Asm, entries: &mut SupportEntries) {
    for op in [DivOp::Div, DivOp::Mod] {
        for width in [Width::W32, Width::W64] {
            entries[SupportEntry::divide(op, width) as usize] = entry(out);
            div_mod(out, op, width);
            entries[SupportEntry::signed_divide(op, width) as usize] = entry(out);
            signed_div_rem(out, op, width, false);
            entries[SupportEntry::signed_divide_imm(op, width) as usize] = entry(out);
            signed_div_rem(out, op, width, true);
        }
    }
}

/// `RTEMP = dividend / divisor` or `RTEMP = dividend % divisor`, with both operands given.
///
/// Divisions by zero terminate the execution.
fn div_mod(out: &mut Asm, op: DivOp, width: Width) {
    let (dividend, divisor) = (frame_operand(0), frame_operand(1));
    let zero = out.new_dynamic_label();
    save_rinsn(out);
    match width {
        Width::W64 => x64asm!(out
            ; cmp QWORD [BYTE divisor + rbp], BYTE 0
            ; je =>zero
            ; mov rax, [BYTE dividend + rbp]
        ),
        Width::W32 => x64asm!(out
            ; cmp DWORD [BYTE divisor + rbp], BYTE 0
            ; je =>zero
            ; mov eax, [BYTE dividend + rbp]
        ),
    }
    // `RMETER` is the only thing left to spill.
    x64asm!(out
        ; push rdx
        ; xor edx, edx
    );
    // The 32-bit forms zero-extend their results to the whole register.
    match width {
        Width::W64 => x64asm!(out; div QWORD [BYTE divisor + rbp]),
        Width::W32 => x64asm!(out; div DWORD [BYTE divisor + rbp]),
    }
    match (width, op) {
        (_, DivOp::Div) => x64asm!(out; mov RTEMP, rax),
        (Width::W64, DivOp::Mod) => x64asm!(out; mov RTEMP, rdx),
        (Width::W32, DivOp::Mod) => x64asm!(out; mov WTEMP, edx),
    }
    x64asm!(out
        ; pop rdx
        ;; restore_rinsn_and_return(out)
        ; =>zero
        ;; validate_meter(out)
        ;; terminate(out, SIG_DIVIDE_BY_ZERO)
    );
}

/// `RTEMP = dividend s/ divisor` or `RTEMP = dividend s% divisor`, with the dividend given.
///
/// The divisor is the immediate of the instruction preceding the address in `RTEMP` if `imm`, and
/// the operand after the dividend otherwise.
///
/// Divisions by zero and `_::MIN / -1` terminate the execution.
fn signed_div_rem(out: &mut Asm, op: DivOp, width: Width, imm: bool) {
    let dividend = frame_operand(0);
    let [zero, overflow, divide] = std::array::from_fn(|_| out.new_dynamic_label());
    save_rinsn(out);
    match width {
        Width::W64 => x64asm!(out; mov rax, [BYTE dividend + rbp]),
        Width::W32 => x64asm!(out; mov eax, [BYTE dividend + rbp]),
    }
    // The displacement of the divisor, unless it is in `RTEMP`.
    let divisor = if imm {
        // `RTEMP` is needed to terminate the execution.
        x64asm!(out
            ; push RTEMP
            ; movsxd RTEMP, DWORD [BYTE -4 + RTEMP]
        );
        match width {
            Width::W64 => x64asm!(out; cmp RTEMP, BYTE -1),
            Width::W32 => x64asm!(out; cmp WTEMP, BYTE -1),
        }
        None
    } else {
        let divisor = frame_operand(1);
        match width {
            Width::W64 => x64asm!(out
                ; cmp QWORD [BYTE divisor + rbp], BYTE 0
                ; je =>zero
                ; cmp QWORD [BYTE divisor + rbp], BYTE -1
            ),
            Width::W32 => x64asm!(out
                ; cmp DWORD [BYTE divisor + rbp], BYTE 0
                ; je =>zero
                ; cmp DWORD [BYTE divisor + rbp], BYTE -1
            ),
        }
        Some(divisor)
    };
    // Only `_::MIN` overflows when negated, which the second `neg` undoes otherwise.
    x64asm!(out; jne =>divide);
    match width {
        Width::W64 => x64asm!(out
            ; neg rax
            ; jo =>overflow
            ; neg rax
        ),
        Width::W32 => x64asm!(out
            ; neg eax
            ; jo =>overflow
            ; neg eax
        ),
    }
    // `RMETER` is the only thing left to spill.
    x64asm!(out
        ; =>divide
        ; push rdx
    );
    // The 32-bit forms zero-extend their results to the whole register.
    match (width, divisor) {
        (Width::W64, None) => x64asm!(out
            ; cqo
            ; idiv RTEMP
        ),
        (Width::W64, Some(divisor)) => x64asm!(out
            ; cqo
            ; idiv QWORD [BYTE divisor + rbp]
        ),
        (Width::W32, None) => x64asm!(out
            ; cdq
            ; idiv WTEMP
        ),
        (Width::W32, Some(divisor)) => x64asm!(out
            ; cdq
            ; idiv DWORD [BYTE divisor + rbp]
        ),
    }
    // The result in `rax`, as `RTEMP` might still have to be popped.
    match (width, op) {
        (_, DivOp::Div) => {}
        (Width::W64, DivOp::Mod) => x64asm!(out; mov rax, rdx),
        (Width::W32, DivOp::Mod) => x64asm!(out; mov eax, edx),
    }
    x64asm!(out; pop rdx);
    if imm {
        x64asm!(out
            // Dropping the saved `RTEMP`, which the result replaces.
            ; pop RTEMP
            ; mov RTEMP, rax
            ;; restore_rinsn_and_return(out)
            ; =>overflow
            ; pop RTEMP
            ;; validate_meter(out)
            ;; terminate(out, SIG_DIVIDE_OVERFLOW)
        );
    } else {
        x64asm!(out
            ; mov RTEMP, rax
            ;; restore_rinsn_and_return(out)
            ; =>overflow
            ;; validate_meter(out)
            ;; terminate(out, SIG_DIVIDE_OVERFLOW)
            ; =>zero
            ;; validate_meter(out)
            ;; terminate(out, SIG_DIVIDE_BY_ZERO)
        );
    }
}

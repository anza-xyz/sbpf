//! The supporting functions for loads and stores.

use super::*;
use dynasmrt::DynamicLabel;

/// Generate the functions for every [`Support::Load`], [`Support::StoreImm`] and
/// [`Support::StoreReg`], registering them with `set`.
pub(super) fn generate(out: &mut Asm, set: &mut impl FnMut(Support, usize)) {
    let failed = out.new_dynamic_label();
    for size in AccessSize::ALL {
        set(
            Support::Load(size),
            generate_access(out, Access::Load(size), failed),
        );
        set(
            Support::StoreImm(size),
            generate_access(out, Access::StoreImm(size), failed),
        );
        set(
            Support::StoreReg(size),
            generate_access(out, Access::StoreReg(size), failed),
        );
    }
    a64asm!(out
        ; =>failed
        // Running out of budget takes precedence over the memory error.
        ;; validate_meter(out)
        ;; terminate(out, SIG_PROGRAM_RESULT)
    );
}

#[derive(Clone, Copy)]
enum Access {
    Load(AccessSize),
    StoreImm(AccessSize),
    StoreReg(AccessSize),
}

/// Do the `access` at the address in `x1` plus the offset of the instruction preceding the address
/// in `RTEMP`, see [`Support`]. Jumps to `failed` if the access fails.
fn generate_access(out: &mut Asm, access: Access, failed: DynamicLabel) -> usize {
    let start = function_start(out);
    // The arguments are the VM, the address, the value to store if any, and the `MeterSlots`
    // that `push_for_host_call` leaves on the stack.
    let (function, meter_slots) = match access {
        Access::Load(size) => (size.load_offset(), 2),
        Access::StoreImm(size) | Access::StoreReg(size) => (size.store_offset(), 3),
    };
    push_for_host_call(out);
    if let Access::StoreImm(_) = access {
        a64asm!(out; ldursw x2, [RTEMP, -4]);
    }
    a64asm!(out
        ; ldursh x4, [RTEMP, -6]
        ; add x1, x1, x4
        ; ldr x0, [RFRAME, frame_offset!(vm)]
        ; add XSP(meter_slots), sp, METER_SLOTS
        ; ldr RTARGET, [RFRAME, frame_offset!(memory_functions)]
        ; ldr RTARGET, [RTARGET, u32::try_from(function).unwrap()]
        ; blr RTARGET
        ;; pop_after_host_call(out)
        ; tst w1, 0xff
        ; b.ne =>failed
        ; ret
    );
    start
}

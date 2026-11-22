//! Host memory-access trampolines. a1 holds the base address and a2 the register store value.

use super::*;
use dynasmrt::DynamicLabel;

pub(super) fn generate(out: &mut Asm, set: &mut impl FnMut(Support, usize)) {
    let failed = out.new_dynamic_label();
    for size in AccessSize::ALL {
        for support in [
            Support::Load(size),
            Support::StoreReg(size),
            Support::StoreImm(size),
        ] {
            set(support, generate_access(out, support, failed));
        }
    }
    rv_asm!(out
        ; =>failed
        ;; validate_meter(out)
        ;; terminate(out, SIG_PROGRAM_RESULT)
    );
}

fn generate_access(out: &mut Asm, access: Support, failed: DynamicLabel) -> usize {
    let start = function_start(out);
    push_for_host_call(out);
    let function = match access {
        Support::Load(size) => {
            rv_asm!(out; mv a2, sp);
            size.load_offset()
        }
        Support::StoreImm(size) => {
            rv_asm!(out; lw a2, [RTEMP, -4]; mv a3, sp);
            size.store_offset()
        }
        Support::StoreReg(size) => {
            rv_asm!(out; mv a3, sp);
            size.store_offset()
        }
        _ => unreachable!(),
    };
    rv_asm!(out
        ; lh a4, [RTEMP, -6]
        ; add a1, a1, a4
        ; ld a0, [RFRAME, frame_offset!(vm)]
        ; ld RTARGET, [RFRAME, frame_offset!(memory_functions)]
        ; ld RTARGET, [RTARGET, i32::try_from(function).unwrap()]
        ; jalr RTARGET
        ;; pop_after_host_call(out)
        ; andi a1, a1, 255
        ; bnez a1, =>failed
        ; ret
    );
    start
}

//! Relocations within the JIT templates.

use super::Relocation;
use crate::codegen::generate::PatchFields;
use crate::codegen::templates::{Instantiation, JitTemplates, PADDING_DUE};
use crate::ebpf;
use dynasmrt::relocations::{Relocation as _, RelocationKind};
use std::convert::TryFrom;

/// Every template reserves this many relocations, so keep it at the maximum that any template
/// needs (`templates_fit_max_relocations` checks both directions).
pub(in crate::codegen) const MAX_RELOCATIONS: usize = if cfg!(feature = "tracer") { 5 } else { 4 };

pub(in crate::codegen) const MAX_JIT_TEMPLATE_SIZE: usize =
    if cfg!(feature = "tracer") { 64 } else { 48 };

#[derive(Clone, Copy, Debug)]
#[repr(u8)]
pub(in crate::codegen) enum TemplateRelocationKind {
    /// Offset from address in `RINSN` to the BPF instruction. Can be used to determine where the
    /// offset or immediate fields of the "current" BPF instruction are.
    InsnOffset,
    /// When BPF instruction represents a branch, and the branch is taken, the control flow has to
    /// transfer to the machine code representing the target BPF instruction's code. Offset to this
    /// machine code is what this relocation overwrites based on the BPF instruction being
    /// templated.
    TakenBranch,
    /// For `jmp ->sig_meter_exceeded`.
    SigMeterExceeded,
    /// For `jmp ->sig_invalid_insn`.
    SigInvalidInsn,
}

/// A relocation that can only be resolved once the template is instantiated for a specific eBPF
/// instruction at a specific location: a 32-bit field in the template, which holds the addend, to
/// which the target of the relocation is added.
#[derive(Clone, Copy, Debug)]
pub(in crate::codegen) struct TemplateRelocation {
    /// Offset of the field within the template.
    field: u8,
    kind: TemplateRelocationKind,
}

impl TemplateRelocationKind {
    /// For a reference to the global label `name` in a template.
    pub(in crate::codegen) fn of_global(name: &str) -> Self {
        match name {
            "template_taken_branch" => Self::TakenBranch,
            "sig_meter_exceeded" => Self::SigMeterExceeded,
            "sig_invalid_insn" => Self::SigInvalidInsn,
            _ => panic!("global reference to an unknown symbol {}", name),
        }
    }
}

impl TemplateRelocation {
    /// Placeholder for unused entries.
    pub(in crate::codegen) const UNUSED: Self = Self {
        field: 0,
        kind: TemplateRelocationKind::InsnOffset,
    };

    /// `patch` is a relocation reported by `dynasm` at the end of `code`, the template generated so
    /// far.
    pub(in crate::codegen) fn new(
        kind: TemplateRelocationKind,
        patch: PatchFields<Relocation>,
        code: &mut [u8],
    ) -> Self {
        let location = code.len();
        let relative = match kind {
            TemplateRelocationKind::TakenBranch
            | TemplateRelocationKind::SigMeterExceeded
            | TemplateRelocationKind::SigInvalidInsn => true,
            TemplateRelocationKind::InsnOffset => false,
        };
        assert!(
            match patch.relocation.kind() {
                RelocationKind::Relative => relative,
                RelocationKind::Absolute => !relative,
                RelocationKind::RelToAbs | RelocationKind::AbsToRel => false,
            },
            "unsupported template relocation"
        );
        assert_eq!(
            patch.relocation.size(),
            4,
            "unsupported template relocation"
        );
        let reference = if relative {
            location.checked_sub(usize::from(patch.ref_offset)).unwrap()
        } else {
            0
        };
        let field = location
            .checked_sub(usize::from(patch.field_offset))
            .unwrap();
        // The template ends no earlier than `location`, so the field is within it. `apply` relies
        // on this.
        assert!(
            field.checked_add(4).unwrap() <= location,
            "unsupported template relocation"
        );
        let addend =
            i32::try_from(patch.target_offset.checked_sub(reference as isize).unwrap()).unwrap();
        code[field..field.wrapping_add(4)].copy_from_slice(&addend.to_le_bytes());
        Self {
            field: u8::try_from(field).unwrap(),
            kind,
        }
    }

    #[inline(always)]
    pub(in crate::codegen) fn apply<const SIZE: usize>(
        &self,
        template: &[u8; SIZE],
        out: &mut [u8; SIZE],
        at: &Instantiation,
    ) {
        // Computed in `i64` to avoid overflow concerns.
        let target = match self.kind {
            TemplateRelocationKind::InsnOffset => (at.pc as i64)
                .wrapping_mul(ebpf::INSN_SIZE as i64)
                .wrapping_sub(at.random_key as u64 as i64),
            TemplateRelocationKind::TakenBranch => {
                // The verifier rejects invalid jump offsets, but checking them is cheap.
                let target = at
                    .pc
                    .checked_add_signed(isize::from(at.off).wrapping_add(1))
                    .and_then(|target_pc| at.pc_section.get(target_pc))
                    .copied()
                    .unwrap_or(JitTemplates::<SIZE>::INVALID_CALL_TARGET);
                i64::from(target & !PADDING_DUE).wrapping_sub(at.position as i64)
            }
            TemplateRelocationKind::SigMeterExceeded => {
                (at.sig_meter_exceeded as i64).wrapping_sub(at.position as i64)
            }
            TemplateRelocationKind::SigInvalidInsn => {
                (at.sig_invalid_insn as i64).wrapping_sub(at.position as i64)
            }
        };
        add_to_field(template, out, usize::from(self.field), target);
    }
}

#[inline(always)]
fn add_to_field<const SIZE: usize>(
    template: &[u8; SIZE],
    out: &mut [u8; SIZE],
    field: usize,
    value: i64,
) {
    debug_assert!(field.wrapping_add(4) <= SIZE);
    unsafe {
        // SAFETY:
        //
        // Contract from `<*const u8>::add`: The offset in bytes, `count * size_of::<T>()`, computed
        // on mathematical integers (without "wrapping around"), must fit in an `isize`.
        //
        // Contract from `<*const u8>::add`: If the computed offset is non-zero, then `self` must be
        // derived from a pointer to some allocation, and the entire memory range between `self` and
        // the result must be in bounds of that allocation. In particular, this range must not "wrap
        // around" the edge of the address space.
        //
        // Contract from `<*const i32>::read_unaligned`: See `ptr::read_unaligned` for safety
        // concerns and examples.
        //
        // Contract from `ptr::read_unaligned`: `src` must be valid for reads.
        //
        // Contract from `ptr::read_unaligned`: `src` must point to a properly initialized value of
        // type `T`.
        //
        // Contract from `<*mut u8>::add`: The offset in bytes, `count * size_of::<T>()`, computed
        // on mathematical integers (without "wrapping around"), must fit in an `isize`.
        //
        // Contract from `<*mut u8>::add`: If the computed offset is non-zero, then `self` must be
        // derived from a pointer to some allocation, and the entire memory range between `self` and
        // the result must be in bounds of that allocation. In particular, this range must not "wrap
        // around" the edge of the address space.
        //
        // Contract from `<*mut i32>::write_unaligned`: See `ptr::write_unaligned` for safety
        // concerns and examples.
        //
        // Contract from `ptr::write_unaligned`: `dst` must be valid for writes.
        //
        // Evidence: `TemplateRelocation::new` asserts that a field ends within its template, so
        // `field + 4` is at most the length of the template. That is at most `SIZE`, so `field` is
        // an offset within the arrays `template` and `out`, which fits an `isize`, and the 4 bytes
        // at it are within either array. They are initialized bytes, and any 4 of them are a valid
        // `i32`. `out` is borrowed mutably, so writing to it is allowed.
        let addend = template.as_ptr().add(field).cast::<i32>().read_unaligned();
        debug_assert!(
            i32::try_from(i64::from(addend).wrapping_add(value)).is_ok(),
            "impossible relocation"
        );
        let field = out.as_mut_ptr().add(field).cast::<i32>();
        field.write_unaligned(addend.wrapping_add(value as i32));
    }
}

//! Instantiation of RV64 instruction templates.

use super::{IslandEntry, Relocation};
use crate::codegen::generate::PatchFields;
use crate::codegen::templates::{Instantiation, JitTemplates, PADDING_DUE};
use crate::ebpf;
use std::convert::{TryFrom, TryInto};

pub(in crate::codegen) const MAX_RELOCATIONS: usize = if cfg!(feature = "tracer") { 4 } else { 3 };
pub(in crate::codegen) const MAX_JIT_TEMPLATE_SIZE: usize =
    if cfg!(feature = "tracer") { 76 } else { 56 };

#[derive(Clone, Copy, Debug)]
pub(in crate::codegen) enum TemplateRelocationKind {
    /// LUI and ADDIW materializing a signed byte offset from RINSN.
    InsnOffset,
    /// JAL to the guest branch target, via the latest island when out of range.
    TakenBranch,
    /// JAL to a supporting code trampoline in the latest island.
    Island(IslandEntry),
}

impl TemplateRelocationKind {
    pub(in crate::codegen) fn of_global(name: &str) -> Self {
        if name == "template_taken_branch" {
            Self::TakenBranch
        } else {
            Self::Island(IslandEntry::of_global(name).expect("unknown template label"))
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub(in crate::codegen) struct TemplateRelocation {
    field: u8,
    kind: TemplateRelocationKind,
}

impl TemplateRelocation {
    pub(in crate::codegen) const UNUSED: Self = Self {
        field: 0,
        kind: TemplateRelocationKind::InsnOffset,
    };

    pub(in crate::codegen) fn new(
        kind: TemplateRelocationKind,
        patch: PatchFields<Relocation>,
        code: &mut [u8],
    ) -> Self {
        let field = code
            .len()
            .checked_sub(usize::from(patch.field_offset))
            .unwrap();
        match kind {
            TemplateRelocationKind::InsnOffset => {
                assert_eq!(read(code, field) & 0x7f, 0x37, "expected LUI");
                assert_eq!(
                    read(code, field.wrapping_add(4)) & 0x707f,
                    0x1b,
                    "expected ADDIW"
                );
            }
            _ => assert_eq!(read(code, field) & 0xfff, 0x6f, "expected JAL x0"),
        }
        Self {
            field: u8::try_from(field).unwrap(),
            kind,
        }
    }

    pub(in crate::codegen) fn apply<const SIZE: usize>(
        &self,
        template: &[u8; SIZE],
        out: &mut [u8; SIZE],
        at: &Instantiation,
    ) {
        let field = usize::from(self.field);
        let position = at.position.wrapping_add(field) as isize;
        let jump_to = |target: usize| jal((target as isize).wrapping_sub(position));
        let word = match self.kind {
            TemplateRelocationKind::InsnOffset => {
                let upper = read(template, field);
                let lower = read(template, field.wrapping_add(4));
                let addend = ((upper & 0xffff_f000) as i32).wrapping_add((lower as i32) >> 20);
                let byte_pc = at.pc.wrapping_mul(ebpf::INSN_SIZE) as i64;
                let offset = byte_pc
                    .wrapping_sub(i64::from(at.random_key))
                    .wrapping_add(i64::from(addend));
                let offset =
                    i32::try_from(offset).expect("guest offset does not fit LUI/ADDIW") as u32;
                // ADDIW sign-extends its 12-bit immediate. Carry bit 11 into the LUI.
                write(
                    out,
                    field,
                    (upper & 0xfff) | (offset.wrapping_add(0x800) & 0xffff_f000),
                );
                write(
                    out,
                    field.wrapping_add(4),
                    (lower & 0x000f_ffff) | (offset << 20),
                );
                return;
            }
            TemplateRelocationKind::TakenBranch => {
                let target = at
                    .pc
                    .checked_add_signed(isize::from(at.off).wrapping_add(1))
                    .and_then(|pc| at.pc_section.get(pc))
                    .copied()
                    .unwrap_or(JitTemplates::<SIZE>::INVALID_CALL_TARGET);
                jump_to((target & !PADDING_DUE) as usize)
                    .or_else(|| jump_to(at.island[IslandEntry::FarJump as usize]))
            }
            TemplateRelocationKind::Island(entry) => jump_to(at.island[entry as usize]),
        };
        write(out, field, word.expect("island out of JAL range"));
    }
}

/// Encode JAL x0 with its signed, two-byte-aligned J-type displacement.
fn jal(offset: isize) -> Option<u32> {
    if !(-(1 << 20)..(1 << 20)).contains(&offset) || offset & 1 != 0 {
        return None;
    }
    let imm = offset as u32;
    let imm_20 = (imm & 0x100000) << 11;
    let imm_10_1 = (imm & 0x7fe) << 20;
    let imm_11 = (imm & 0x800) << 9;
    let imm_19_12 = imm & 0xff000;
    Some(imm_20 | imm_10_1 | imm_11 | imm_19_12 | 0x6f)
}

fn read(code: &[u8], field: usize) -> u32 {
    u32::from_le_bytes(code[field..field.wrapping_add(4)].try_into().unwrap())
}

fn write(code: &mut [u8], field: usize, word: u32) {
    code[field..field.wrapping_add(4)].copy_from_slice(&word.to_le_bytes());
}

//! Relocations within the JIT templates.

use super::{IslandEntry, Relocation};
use crate::codegen::generate::PatchFields;
use crate::codegen::templates::{Instantiation, JitTemplates, PADDING_DUE};
use crate::ebpf;
use std::convert::{TryFrom, TryInto};

/// Every template reserves this many relocations, so keep it at the maximum that any template
/// needs (`templates_fit_max_relocations` checks both directions).
pub(in crate::codegen) const MAX_RELOCATIONS: usize = if cfg!(feature = "tracer") { 4 } else { 3 };

pub(in crate::codegen) const MAX_JIT_TEMPLATE_SIZE: usize =
    if cfg!(feature = "tracer") { 80 } else { 48 };

#[derive(Clone, Copy, Debug)]
pub(in crate::codegen) enum TemplateRelocationKind {
    /// `movz` and `movk` of a 32-bit offset from the address in `RINSN` to the BPF instruction,
    /// on top of the offset they encode. Can be used to determine where the offset or immediate
    /// fields of the "current" BPF instruction are.
    InsnOffset,
    /// `b ->template_taken_branch`, to the machine code of the BPF instruction that a taken
    /// branch transfers the control to, or to the [`IslandEntry::FarJump`] if that is out of
    /// reach.
    TakenBranch,
    /// A branch to the entry of the latest island.
    Island(IslandEntry),
}

/// How a relocated instruction encodes the target.
#[derive(Clone, Copy, Debug)]
enum Encoding {
    /// `movz` followed by `movk`, for [`TemplateRelocationKind::InsnOffset`].
    MovPair,
    /// `b`.
    Imm26,
    /// `b.cond`, `cbz` and `cbnz`.
    Imm19,
}

impl Encoding {
    /// The encoding of the branch `instruction`.
    fn of_branch(instruction: u32) -> Self {
        if instruction & 0xfc00_0000 == 0x1400_0000 {
            Self::Imm26
        } else if instruction & 0xff00_0010 == 0x5400_0000
            || instruction & 0x7e00_0000 == 0x3400_0000
        {
            Self::Imm19
        } else {
            panic!("unsupported template relocation of {:#x}", instruction)
        }
    }

    /// `instruction` branching `offset` bytes away, or `None` if that is out of its reach.
    #[inline(always)]
    fn branch(self, instruction: u32, offset: i64) -> Option<u32> {
        let (bits, shift): (u32, u32) = match self {
            Self::Imm26 => (26, 0),
            Self::Imm19 => (19, 5),
            Self::MovPair => unreachable!(),
        };
        let words = offset >> 2;
        let reach = 1i64 << bits.wrapping_sub(1);
        if offset & 3 != 0 || words < reach.wrapping_neg() || words >= reach {
            return None;
        }
        let mask = ((1u32 << bits).wrapping_sub(1)) << shift;
        Some(instruction & !mask | ((words as u32) << shift & mask))
    }
}

/// A relocation that can only be resolved once the template is instantiated for a specific eBPF
/// instruction at a specific location, by patching the immediates of instructions.
#[derive(Clone, Copy, Debug)]
pub(in crate::codegen) struct TemplateRelocation {
    /// Offset of the (first) instruction within the template.
    field: u8,
    kind: TemplateRelocationKind,
    encoding: Encoding,
}

impl TemplateRelocationKind {
    /// For a reference to the global label `name` in a template.
    pub(in crate::codegen) fn of_global(name: &str) -> Self {
        match name {
            "template_taken_branch" => Self::TakenBranch,
            _ => match IslandEntry::of_global(name) {
                Some(entry) => Self::Island(entry),
                None => panic!("global reference to an unknown symbol {}", name),
            },
        }
    }
}

/// The bits of the `imm16` field of `movz` and `movk`.
const MOV_IMM16: u32 = 0xffff << 5;

impl TemplateRelocation {
    /// Placeholder for unused entries.
    pub(in crate::codegen) const UNUSED: Self = Self {
        field: 0,
        kind: TemplateRelocationKind::InsnOffset,
        encoding: Encoding::MovPair,
    };

    /// `patch.field_offset` is how far back from the end of `code`, the template generated so
    /// far, the relocated instruction(s) start.
    pub(in crate::codegen) fn new(
        kind: TemplateRelocationKind,
        patch: PatchFields<Relocation>,
        code: &mut [u8],
    ) -> Self {
        let field = code
            .len()
            .checked_sub(usize::from(patch.field_offset))
            .unwrap();
        let encoding = match kind {
            TemplateRelocationKind::InsnOffset => Encoding::MovPair,
            _ => Encoding::of_branch(read(code, field)),
        };
        let len = match encoding {
            Encoding::MovPair => 8,
            Encoding::Imm26 | Encoding::Imm19 => 4,
        };
        // `apply` relies on the instructions being within the template.
        assert!(
            field.checked_add(len).unwrap() <= code.len(),
            "unsupported template relocation"
        );
        Self {
            field: u8::try_from(field).unwrap(),
            kind,
            encoding,
        }
    }

    #[inline(always)]
    pub(in crate::codegen) fn apply<const SIZE: usize>(
        &self,
        template: &[u8; SIZE],
        out: &mut [u8; SIZE],
        at: &Instantiation,
    ) {
        let field = usize::from(self.field);
        let first = read(template, field);
        let position = at.position.wrapping_add(field) as i64;
        let to = |target: usize| (target as i64).wrapping_sub(position);
        let branch = match self.kind {
            TemplateRelocationKind::InsnOffset => {
                let second_field = field.wrapping_add(4);
                let second = read(template, second_field);
                let value = (at.pc as i64)
                    .wrapping_mul(ebpf::INSN_SIZE as i64)
                    .wrapping_sub(i64::from(at.random_key));
                let addend = (first & MOV_IMM16) >> 5 | (second & MOV_IMM16) << 11;
                let offset = (addend as i32 as i64).wrapping_add(value);
                debug_assert!(i32::try_from(offset).is_ok(), "impossible relocation");
                let offset = offset as u32;
                write(out, field, first & !MOV_IMM16 | (offset & 0xffff) << 5);
                write(out, second_field, second & !MOV_IMM16 | (offset >> 16) << 5);
                return;
            }
            TemplateRelocationKind::TakenBranch => {
                // The verifier rejects invalid jump offsets, but checking them is cheap.
                let target = at
                    .pc
                    .checked_add_signed(isize::from(at.off).wrapping_add(1))
                    .and_then(|target_pc| at.pc_section.get(target_pc))
                    .copied()
                    .unwrap_or(JitTemplates::<SIZE>::INVALID_CALL_TARGET);
                let target = (target & !PADDING_DUE) as usize;
                self.encoding.branch(first, to(target)).or_else(|| {
                    let far_jump = at.island[IslandEntry::FarJump as usize];
                    self.encoding.branch(first, to(far_jump))
                })
            }
            TemplateRelocationKind::Island(entry) => {
                self.encoding.branch(first, to(at.island[entry as usize]))
            }
        };
        write(out, field, branch.expect("island out of reach"));
    }
}

#[inline(always)]
fn read(code: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(code[at..at.wrapping_add(4)].try_into().unwrap())
}

#[inline(always)]
fn write(code: &mut [u8], at: usize, instruction: u32) {
    code[at..at.wrapping_add(4)].copy_from_slice(&instruction.to_le_bytes());
}

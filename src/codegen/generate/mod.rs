//! Produce JIT templates and interpreters for the architecture (`arch`.)

mod interpreter;
mod jit;

pub(super) use interpreter::{interpreter, interpreter_step, InterpreterGenerator};
pub use jit::jit_templates;

use super::arch::TemplateRelocationKind;
use crate::program::SBPFVersion;
use dynasmrt::components::{LabelRegistry, PatchLoc, RelocRegistry};
use dynasmrt::relocations::{Relocation, RelocationKind};
use dynasmrt::{AssemblyOffset, DynamicLabel};

/// A BPF register.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) struct Reg(pub(super) u8);

impl Reg {
    /// The number of the BPF registers.
    pub(super) const COUNT: usize = 11;
    pub(super) const ALL: [Reg; Self::COUNT] = const {
        let mut out = [Reg(0); Self::COUNT];
        let mut i = 0;
        while i < Self::COUNT {
            out[i] = Reg(i as u8);
            i += 1;
        }
        out
    };

    /// `None` if there's no such register.
    pub(super) const fn new(number: u8) -> Option<Self> {
        if (number as usize) < Self::COUNT {
            Some(Reg(number))
        } else {
            None
        }
    }
}

/// First 16 bits of a BPF instruction containing the opcode and registers.
///
/// Used to dispatch to the interpreter steps/JIT templates.
#[derive(Clone, Copy)]
#[repr(transparent)]
pub(super) struct TemplateOpcode(pub(super) u16);

impl TemplateOpcode {
    pub(super) const COUNT: usize = 1 + u16::MAX as usize;
    pub(super) const fn of(insn: u64) -> Self {
        Self(insn as u16)
    }
    /// Iterator over all instructions in order of the dispatch table.
    pub(super) fn all() -> impl Iterator<Item = Self> {
        (0..=u16::MAX).map(Self)
    }
    pub(super) const fn index(self) -> usize {
        self.0 as usize
    }
    pub(super) const fn op(self) -> u8 {
        self.0 as u8
    }
    /// The destination register field.
    pub(super) const fn dst(self) -> Option<Reg> {
        Reg::new((self.0 >> 8 & 0xf) as u8)
    }
    /// The source register field.
    pub(super) const fn src(self) -> Option<Reg> {
        Reg::new((self.0 >> 12) as u8)
    }
}

/// Relocations against dynamic labels defined within the code being generated.
///
/// These are resolved once generation of machine code for the BPF instruction is complete.
struct LabelRelocs<R: Relocation> {
    labels: LabelRegistry,
    relocs: RelocRegistry<R>,
}

impl<R: Relocation + Copy> LabelRelocs<R> {
    fn new() -> Self {
        Self {
            labels: LabelRegistry::new(),
            relocs: RelocRegistry::new(),
        }
    }

    fn new_dynamic_label(&mut self) -> DynamicLabel {
        self.labels.new_dynamic_label()
    }

    fn dynamic_label(&mut self, id: DynamicLabel, at: usize) {
        self.labels.define_dynamic(id, AssemblyOffset(at)).unwrap()
    }

    fn dynamic_reloc(&mut self, at: usize, id: DynamicLabel, patch: PatchFields<R>) {
        self.relocs.add_dynamic(id, patch.at(at));
    }

    fn resolve(&mut self, code: &mut [u8], start: usize) {
        for (loc, id) in self.relocs.take_dynamics() {
            assert!(
                matches!(loc.relocation.kind(), RelocationKind::Relative),
                "position independent code may only contain relative label references"
            );
            let target = self.labels.resolve_dynamic(id).unwrap();
            let range = loc.range(start);
            loc.patch(&mut code[range], 0, target.0)
                .expect("impossible relocation");
        }
        self.labels.clear();
    }
}

/// Relocation parameters as produced by `dynasm`, sans the location.
#[derive(Clone, Copy)]
pub(super) struct PatchFields<R> {
    pub(super) target_offset: isize,
    pub(super) field_offset: u8,
    pub(super) ref_offset: u8,
    pub(super) relocation: R,
}

impl<R: Relocation + Copy> PatchFields<R> {
    pub(super) fn new(target_offset: isize, field_offset: u8, ref_offset: u8, kind: u8) -> Self {
        Self {
            target_offset,
            field_offset,
            ref_offset,
            relocation: R::from_encoding(kind),
        }
    }

    /// `at` is the offset right past the instruction containing the field to patch (i.e. the
    /// offset at the time `dynasm` reports the relocation.)
    pub(super) fn at(self, at: usize) -> PatchLoc<R> {
        PatchLoc::new(
            AssemblyOffset(at),
            self.target_offset,
            self.field_offset,
            self.ref_offset,
            self.relocation,
        )
    }
}

/// Customization of how the templates and the interpreter code is generated.
pub(super) trait Generator {
    fn extend(&mut self, buffer: &[u8]);
    fn offset(&self) -> usize;
    fn push(&mut self, byte: u8) {
        self.extend(&[byte]);
    }
    fn push_i8(&mut self, value: i8) {
        self.extend(&[value as u8]);
    }
    fn push_i32(&mut self, value: i32) {
        self.extend(&value.to_le_bytes());
    }
    fn global_reloc(
        &mut self,
        name: &'static str,
        target_offset: isize,
        field_offset: u8,
        ref_offset: u8,
        kind: u8,
    );
    fn dynamic_reloc(
        &mut self,
        id: DynamicLabel,
        target_offset: isize,
        field_offset: u8,
        ref_offset: u8,
        kind: u8,
    );
    /// Record a template relocation for bytes immediately preceding the current offset.
    ///
    /// The field is overwritten based on BPF instruction data as the templates are assembled. This
    /// is unlike the other types of relocations which have to be resolved or resolvable when the
    /// template is finalized.
    fn template_reloc(
        &mut self,
        kind: TemplateRelocationKind,
        target_offset: isize,
        field_offset: u8,
        ref_offset: u8,
        encoding: u8,
    );
    fn new_dynamic_label(&mut self) -> DynamicLabel;
    fn dynamic_label(&mut self, id: DynamicLabel);

    /// The SBPF version the code is generated for.
    fn version(&self) -> SBPFVersion;
    fn opcode(&self) -> TemplateOpcode;

    /// Generate the code for a taken branch. `next_insn_in_temp` tells whether `RTEMP` still has
    /// the address of the next instruction (from `load_next_insn_addr`).
    fn bpf_taken_branch(&mut self, next_insn_in_temp: bool);

    /// The code generated so far checks the instruction meter.
    fn meter_checked(&mut self);
}

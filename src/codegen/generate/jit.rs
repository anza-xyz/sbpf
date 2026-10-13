//! Generation of the JIT templates.

use super::{Generator, LabelRelocs, PatchFields, TemplateOpcode};
use crate::codegen::arch::{
    self, TemplateRelocation, TemplateRelocationKind, MAX_JIT_TEMPLATE_SIZE,
};
use crate::codegen::templates::{AuxTemplate, JitTemplates, TemplateBuilder};
use crate::program::SBPFVersion;
use dynasmrt::DynamicLabel;
use std::sync::LazyLock;

struct JITGenerator<'a> {
    version: SBPFVersion,
    template: TemplateBuilder<'a, MAX_JIT_TEMPLATE_SIZE>,
    /// `None` for an `AuxTemplate`.
    opcode: Option<TemplateOpcode>,
    /// Temporary relocations within the code that will be resolved before the template is
    /// finalized.
    ///
    /// Template can have further relocations after finalization, however those relocations may
    /// only be specific to the eBPF instruction being instantiated.
    relocs: LabelRelocs<arch::Relocation>,
}

impl<'a> JITGenerator<'a> {
    fn new(
        version: SBPFVersion,
        template: TemplateBuilder<'a, MAX_JIT_TEMPLATE_SIZE>,
        opcode: Option<TemplateOpcode>,
    ) -> Self {
        Self {
            version,
            template,
            opcode,
            relocs: LabelRelocs::new(),
        }
    }

    /// Generator for a BPF instruction.
    fn for_insn(
        version: SBPFVersion,
        templates: &'a mut JitTemplates<MAX_JIT_TEMPLATE_SIZE>,
        opcode: TemplateOpcode,
    ) -> Self {
        let template = templates.insn_builder(opcode);
        template.layout.extra_bpf_insns = ((crate::ebpf::opcode_size(opcode.op()) / 8) as u8)
            .checked_sub(1)
            .unwrap();
        Self::new(version, template, Some(opcode))
    }

    /// Resolve all the relocations that can be resolved without knowing the specific eBPF
    /// instruction.
    fn finalize(mut self) {
        self.relocs.resolve(self.template.code_mut(), 0);
    }
}

impl Generator for JITGenerator<'_> {
    #[track_caller]
    fn extend(&mut self, buffer: &[u8]) {
        self.template.extend(buffer);
    }

    fn offset(&self) -> usize {
        self.template.offset()
    }

    fn global_reloc(
        &mut self,
        name: &'static str,
        target_offset: isize,
        field_offset: u8,
        ref_offset: u8,
        encoding: u8,
    ) {
        let kind = TemplateRelocationKind::of_global(name);
        self.template_reloc(kind, target_offset, field_offset, ref_offset, encoding);
    }

    fn template_reloc(
        &mut self,
        kind: TemplateRelocationKind,
        target_offset: isize,
        field_offset: u8,
        ref_offset: u8,
        encoding: u8,
    ) {
        let patch = PatchFields::new(target_offset, field_offset, ref_offset, encoding);
        let relocation = TemplateRelocation::new(kind, patch, self.template.code_mut());
        self.template.add_relocation(relocation);
    }

    fn dynamic_reloc(
        &mut self,
        id: DynamicLabel,
        target_offset: isize,
        field_offset: u8,
        ref_offset: u8,
        kind: u8,
    ) {
        let patch = PatchFields::new(target_offset, field_offset, ref_offset, kind);
        self.relocs.dynamic_reloc(self.offset(), id, patch);
    }

    fn new_dynamic_label(&mut self) -> DynamicLabel {
        self.relocs.new_dynamic_label()
    }

    fn dynamic_label(&mut self, id: DynamicLabel) {
        self.relocs.dynamic_label(id, self.offset());
    }

    fn version(&self) -> SBPFVersion {
        self.version
    }

    fn opcode(&self) -> TemplateOpcode {
        self.opcode
            .expect("not generating the template for an instruction")
    }

    fn bpf_taken_branch(&mut self, next_insn_in_temp: bool) {
        arch::jit_taken_branch(self, next_insn_in_temp);
    }

    fn meter_checked(&mut self) {
        self.template.layout.checks_meter = true;
    }
}

// TODO: when dynasm supports const codegen, we can make these be generated at compile time into an
// array.
static JIT_TEMPLATES: [LazyLock<JitTemplates<MAX_JIT_TEMPLATE_SIZE>>; 5] = [
    LazyLock::new(|| generate_jit_templates(SBPFVersion::V0)),
    LazyLock::new(|| panic!("parrot for v1 unlikely to be implemented")),
    LazyLock::new(|| panic!("parrot for v2 unlikely to be implemented")),
    LazyLock::new(|| generate_jit_templates(SBPFVersion::V3)),
    LazyLock::new(|| generate_jit_templates(SBPFVersion::V4)),
];

/// JIT templates for the SBPF `version`.
pub fn jit_templates(version: SBPFVersion) -> &'static JitTemplates<MAX_JIT_TEMPLATE_SIZE> {
    &JIT_TEMPLATES[version as usize]
}

fn generate_jit_templates(version: SBPFVersion) -> JitTemplates<MAX_JIT_TEMPLATE_SIZE> {
    let mut templates = JitTemplates::empty();
    for opcode in TemplateOpcode::all() {
        let mut generator = JITGenerator::for_insn(version, &mut templates, opcode);
        arch::bpf_insn(&mut generator);
        generator.finalize();
    }
    for template in AuxTemplate::ALL {
        let mut generator = JITGenerator::new(version, templates.aux_builder(template), None);
        arch::aux_template(&mut generator, template);
        generator.finalize();
    }
    templates
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Generating the templates panics if any of them needs more than `MAX_RELOCATIONS`, but we
    /// want this number to also be the lowest possible as well.
    #[test]
    fn templates_fit_max_relocations() {
        for version in [SBPFVersion::V0, SBPFVersion::V3, SBPFVersion::V4] {
            let templates = jit_templates(version);
            assert!(templates
                .layouts
                .iter()
                .any(|layout| usize::from(layout.num_relocations) == arch::MAX_RELOCATIONS));
        }
    }
}

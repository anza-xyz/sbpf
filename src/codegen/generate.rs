//! Driving the code generation of the backend (`arch`) into the JIT templates and the
//! interpreters, which are both generated lazily, once per SBPF version.

use super::arch::{self, MAX_JIT_TEMPLATE_SIZE};
use super::{
    AuxTemplate, JitTemplates, TemplateLayout, TemplateRelocation, TemplateRelocationKind,
};
use crate::memory_management::{Mapping, ReadExecute};
use crate::program::SBPFVersion;
use dynasmrt::components::{LabelRegistry, PatchLoc, RelocRegistry};
use dynasmrt::relocations::{Relocation, RelocationKind};
use dynasmrt::{AssemblyOffset, DynamicLabel};
#[cfg(feature = "codegen-debug")]
use std::convert::TryInto;
use std::sync::LazyLock;

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

/// 16 bits of a BPF instruction: the opcode and registers.
///
/// The JIT templates and the interpreter steps use this part of the instruction to dispatch to the
/// handlers/templates.
#[derive(Clone, Copy)]
#[repr(transparent)]
pub(super) struct TemplateOpcode(pub(super) u16);

impl TemplateOpcode {
    pub(super) const COUNT: usize = 1 + u16::MAX as usize;
    /// Of the instruction `insn`.
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

/// Generates a template into the parts of `JitTemplates`.
pub(super) struct TemplateBuilder<'a, const SIZE: usize> {
    pub(super) layout: &'a mut TemplateLayout,
    pub(super) code: &'a mut [u8; SIZE],
    pub(super) relocations: &'a mut [TemplateRelocation; arch::MAX_RELOCATIONS],
}

impl<const SIZE: usize> TemplateBuilder<'_, SIZE> {
    pub(super) fn code_mut(&mut self) -> &mut [u8] {
        &mut self.code[..self.layout.len()]
    }

    /// Add the `relocation` that `arch::TemplateRelocation::new` made of this template.
    pub(super) fn add_relocation(&mut self, relocation: TemplateRelocation) {
        let slot = self
            .relocations
            .get_mut(usize::from(self.layout.num_relocations))
            .expect("template needs more relocations than MAX_RELOCATIONS");
        *slot = relocation;
        self.layout.num_relocations = self.layout.num_relocations.checked_add(1).unwrap();
    }

    #[track_caller]
    pub(super) fn extend(&mut self, buffer: &[u8]) {
        for &byte in buffer {
            self.push(byte);
        }
    }

    pub(super) fn offset(&self) -> usize {
        self.layout.len()
    }

    #[track_caller]
    pub(super) fn push(&mut self, byte: u8) {
        self.code[self.layout.len()] = byte;
        self.layout.bytes = self.layout.bytes.checked_add(1).unwrap();
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

    /// Patch all the recorded relocations into `code`, the code generated from offset `start` on,
    /// and reset the label state.
    ///
    /// The labels do not outlive the code of an instruction, which gets copied elsewhere, so only
    /// the relative relocations are supported.
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

/// Where the backend generates the code of an instruction (or of an `AuxTemplate`) into: a JIT
/// template or an interpreter step.
///
/// The methods up to `dynamic_label` are those that `dynasm` emits calls to, as for
/// `dynasmrt::DynasmApi` and `dynasmrt::DynasmLabelApi`.
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
    /// Of the instruction being generated.
    fn opcode(&self) -> TemplateOpcode;

    /// Generate code to handle branch taken case. `next_insn_in_temp` tells whether the
    /// temporary register still has the address of the next instruction (from
    /// `load_next_insn_addr`).
    fn bpf_taken_branch(&mut self, next_insn_in_temp: bool);

    /// The code generated so far checks the instruction meter.
    fn meter_checked(&mut self);
}

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
    LazyLock::new(|| panic!("dynasm for v1 unlikely to be implemented")),
    LazyLock::new(|| panic!("dynasm for v2 unlikely to be implemented")),
    LazyLock::new(|| generate_jit_templates(SBPFVersion::V3)),
    // TODO: same as v3? maybe Arc-share the v3 templates or something?
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

/// The interpreter step for the instructions with `opcode`, of the interpreter for the SBPF
/// `version`.
pub(super) fn interpreter_step(version: SBPFVersion, opcode: TemplateOpcode) -> *const u8 {
    &interpreter(version).steps[InterpreterGenerator::step_offset(opcode)]
}

pub(super) struct Interpreter {
    /// The steps, which are never freed, as the interpreters are in a static.
    pub(super) steps: Mapping<ReadExecute>,
    /// The length of the code of each step, which is followed by padding to the size of the step.
    #[cfg(feature = "codegen-debug")]
    pub(super) step_lens: Box<[u8]>,
}

/// Generates the interpreter.
///
/// This interpreter uses a dispatch table with one step of `1 << STEP_SIZE_LOG2` bytes per
/// `TemplateOpcode`, each running its instruction and then threading execution to the next one
/// directly, thus implementing a technique known as direct threading.
pub(super) struct InterpreterGenerator {
    buffer: Mapping,
    relocs: LabelRelocs<arch::Relocation>,
    offset: usize,
    version: SBPFVersion,
    /// Of the step being generated.
    opcode: TemplateOpcode,
    /// Is the code generated for this instruction terminal?
    ///
    /// No further instructions other than the epilogue expected to appear after this point.
    terminal: bool,
}

impl InterpreterGenerator {
    pub(super) const STEP_SIZE_LOG2: u8 = arch::INTERPRETER_STEP_SIZE_LOG2;
    pub(super) const STEP_TABLE_SIZE: usize = 0x1_0000 * (1 << Self::STEP_SIZE_LOG2);

    /// Offset into the `buffer` for this opcode.
    fn step_offset(opcode: TemplateOpcode) -> usize {
        opcode.index() << Self::STEP_SIZE_LOG2
    }

    /// Where the steps start, for the generated code to dispatch to them.
    pub(super) fn base(&self) -> *const u8 {
        self.buffer.as_ptr()
    }

    /// Generate into `buffer`, of `STEP_TABLE_SIZE` bytes within the first 2 GiB, so that a backend
    /// may address the steps with absolute 32-bit addresses.
    fn new(version: SBPFVersion, buffer: Mapping) -> Self {
        assert_eq!(buffer.len(), Self::STEP_TABLE_SIZE);
        Self {
            version,
            buffer,
            relocs: LabelRelocs::new(),
            offset: 0,
            opcode: TemplateOpcode(0),
            terminal: false,
        }
    }
}

impl Generator for InterpreterGenerator {
    fn extend(&mut self, buffer: &[u8]) {
        assert!(!self.terminal);
        let step_capacity = 1usize << Self::STEP_SIZE_LOG2;
        let remaining_capacity = step_capacity
            .checked_sub(self.offset % step_capacity)
            .unwrap();
        assert!(buffer.len() <= remaining_capacity, "step is too long!");
        let end = self.offset.checked_add(buffer.len()).unwrap();
        self.buffer[self.offset..end].copy_from_slice(buffer);
        self.offset = end;
    }

    fn offset(&self) -> usize {
        self.offset
    }

    fn global_reloc(
        &mut self,
        name: &'static str,
        target_offset: isize,
        field_offset: u8,
        ref_offset: u8,
        kind: u8,
    ) {
        let target = arch::interpreter_global(name);
        let patch =
            PatchFields::<arch::Relocation>::new(target_offset, field_offset, ref_offset, kind)
                .at(self.offset);
        assert!(
            matches!(patch.relocation.kind(), RelocationKind::Relative),
            "unsupported relocation"
        );
        let base = self.buffer.as_ptr() as usize;
        let field = &mut self.buffer[patch.range(0)];
        let target = target.wrapping_sub(base);
        patch
            .patch(field, base, target)
            .expect("global label out of reach of the interpreter");
    }

    fn template_reloc(&mut self, _: TemplateRelocationKind, _: isize, _: u8, _: u8, _: u8) {
        // Intentionally empty: interpreter does not generate templates.
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
        self.relocs.dynamic_reloc(self.offset, id, patch);
    }

    fn new_dynamic_label(&mut self) -> DynamicLabel {
        self.relocs.new_dynamic_label()
    }

    fn dynamic_label(&mut self, id: DynamicLabel) {
        self.relocs.dynamic_label(id, self.offset);
    }

    fn version(&self) -> SBPFVersion {
        self.version
    }

    fn opcode(&self) -> TemplateOpcode {
        self.opcode
    }

    fn bpf_taken_branch(&mut self, next_insn_in_temp: bool) {
        arch::interpreter_taken_branch(self, next_insn_in_temp);
        self.terminal = true;
    }

    fn meter_checked(&mut self) { /* every step checks the meter */
    }
}

static INTERPRETERS: [LazyLock<Interpreter>; 5] = [
    LazyLock::new(|| generate_interpreter(SBPFVersion::V0)),
    LazyLock::new(|| panic!("dynasm for v1 unlikely to be implemented")),
    LazyLock::new(|| panic!("dynasm for v2 unlikely to be implemented")),
    LazyLock::new(|| generate_interpreter(SBPFVersion::V3)),
    LazyLock::new(|| generate_interpreter(SBPFVersion::V4)),
];

/// The interpreter for the SBPF `version`.
pub(super) fn interpreter(version: SBPFVersion) -> &'static Interpreter {
    &INTERPRETERS[version as usize]
}

fn generate_interpreter(version: SBPFVersion) -> Interpreter {
    let builder = Mapping::builder(InterpreterGenerator::STEP_TABLE_SIZE).low();
    #[cfg(feature = "codegen-debug")]
    let mut debug_image =
        super::debug::DebugImage::new(&format!("interpreter-{version:?}").to_lowercase());
    let buffer = cfg_select! {
        feature = "codegen-debug" => debug_image.map(builder),
        _ => builder.build(),
    }
    .expect("failed to allocate memory for the interpreter");
    let mut generator = InterpreterGenerator::new(version, buffer);
    // The space after the code of a step traps if it is ever executed.
    generator.buffer.fill(arch::TRAP_FILL);
    #[cfg(feature = "codegen-debug")]
    let mut step_lens = vec![0; TemplateOpcode::COUNT];
    for opcode in TemplateOpcode::all() {
        let step_start = InterpreterGenerator::step_offset(opcode);
        generator.opcode = opcode;
        generator.offset = step_start;
        arch::bpf_insn(&mut generator);
        generator.terminal = false;
        arch::interpreter_dispatch(&mut generator);
        let step_len = generator.offset.checked_sub(step_start).unwrap();
        assert!(
            step_len <= 1 << InterpreterGenerator::STEP_SIZE_LOG2,
            "step for {:#x} is too long",
            opcode.0
        );
        let step = &mut generator.buffer[step_start..generator.offset];
        generator.relocs.resolve(step, step_start);
        #[cfg(feature = "codegen-debug")]
        {
            step_lens[opcode.index()] = step_len.try_into().unwrap();
        }
    }

    let interpreter = Interpreter {
        steps: generator
            .buffer
            .protect()
            .expect("failed to make the interpreter executable"),
        #[cfg(feature = "codegen-debug")]
        step_lens: step_lens.into_boxed_slice(),
    };
    #[cfg(feature = "codegen-debug")]
    super::debug::finish_interpreter(debug_image, version, &interpreter);
    interpreter
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

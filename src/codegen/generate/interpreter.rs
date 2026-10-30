//! Generation of the interpreter.

use super::{Generator, LabelRelocs, PatchFields, TemplateOpcode};
use crate::codegen::arch::{self, TemplateRelocationKind};
use crate::memory_management::{Mapping, ReadExecute};
use crate::program::SBPFVersion;
use dynasmrt::relocations::{Relocation, RelocationKind};
use dynasmrt::DynamicLabel;
use std::sync::LazyLock;

/// The interpreter step for the instructions with `opcode`, of the interpreter for the SBPF
/// `version`.
pub(in crate::codegen) fn interpreter_step(
    version: SBPFVersion,
    opcode: TemplateOpcode,
) -> *const u8 {
    &interpreter(version).steps[InterpreterGenerator::step_offset(opcode)]
}

pub(in crate::codegen) struct Interpreter {
    pub(in crate::codegen) steps: Mapping<ReadExecute>,
}

/// Generates the interpreter.
///
/// This interpreter uses a dispatch table with one step of `1 << STEP_SIZE_LOG2` bytes per
/// `TemplateOpcode`, each running its instruction and then dispatching the execution to the next
/// one directly.
pub(in crate::codegen) struct InterpreterGenerator {
    buffer: Mapping,
    relocs: LabelRelocs<arch::Relocation>,
    offset: usize,
    version: SBPFVersion,
    opcode: TemplateOpcode,
    /// Is the code generated for this instruction terminal?
    ///
    /// No further instructions other than the epilogue expected to appear after this point.
    terminal: bool,
}

impl InterpreterGenerator {
    pub(in crate::codegen) const STEP_SIZE_LOG2: u8 = arch::INTERPRETER_STEP_SIZE_LOG2;
    pub(in crate::codegen) const STEP_TABLE_SIZE: usize = 0x1_0000 * (1 << Self::STEP_SIZE_LOG2);

    /// Offset into the `buffer` for this opcode.
    fn step_offset(opcode: TemplateOpcode) -> usize {
        opcode.index() << Self::STEP_SIZE_LOG2
    }

    pub(in crate::codegen) fn base(&self) -> *const u8 {
        self.buffer.as_ptr()
    }

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

    fn meter_checked(&mut self) {
        // Intentionally empty: every step checks the meter.
    }
}

static INTERPRETERS: [LazyLock<Interpreter>; 5] = [
    LazyLock::new(|| generate_interpreter(SBPFVersion::V0)),
    LazyLock::new(|| panic!("parrot for v1 unlikely to be implemented")),
    LazyLock::new(|| panic!("parrot for v2 unlikely to be implemented")),
    LazyLock::new(|| generate_interpreter(SBPFVersion::V3)),
    LazyLock::new(|| generate_interpreter(SBPFVersion::V4)),
];

/// The interpreter for the SBPF `version`.
pub(in crate::codegen) fn interpreter(version: SBPFVersion) -> &'static Interpreter {
    &INTERPRETERS[version as usize]
}

fn generate_interpreter(version: SBPFVersion) -> Interpreter {
    let buffer = Mapping::sub2g(InterpreterGenerator::STEP_TABLE_SIZE);
    let mut generator = InterpreterGenerator::new(version, buffer);
    // The space after the code of a step traps if it is ever executed.
    generator.buffer.fill(arch::TRAP_FILL);
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
    }

    Interpreter {
        steps: generator.buffer.protect(),
    }
}

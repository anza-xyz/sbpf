//! Driving the code generation of the backend (`arch`) into the JIT templates and the
//! interpreters, which are both generated lazily, once per SBPF version.

use super::arch::{self, MAX_JIT_TEMPLATE_SIZE};
use super::{AuxTemplate, JitTemplates, TemplateLayout, TemplateRelocation, TemplateRelocationKind};
use crate::memory_management::{allocate_pages_low, protect_pages, PagePermissions};
use crate::program::SBPFVersion;
use dynasmrt::components::{LabelRegistry, PatchLoc, RelocRegistry};
use dynasmrt::relocations::{Relocation, RelocationKind};
use dynasmrt::{AssemblyOffset, DynamicLabel};
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

    // Generate code to handle branch taken case.
    fn bpf_taken_branch(&mut self);

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

    fn bpf_taken_branch(&mut self) {
        arch::jit_taken_branch(self);
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
    let offset = InterpreterGenerator::step_offset(opcode);
    // SAFETY:
    //
    // Contract from `<*mut u8>::add`: The offset in bytes, `count * size_of::<T>()`, computed on
    // mathematical integers (without "wrapping around"), must fit in an `isize`.
    //
    // Contract from `<*mut u8>::add`: If the computed offset is non-zero, then `self` must be
    // derived from a pointer to some allocation, and the entire memory range between `self` and the
    // result must be in bounds of that allocation. In particular, this range must not "wrap around"
    // the edge of the address space.
    //
    // Evidence: `buffer` is the allocation of `allocate_pages_low` of `STEP_TABLE_SIZE` bytes,
    // which is `TemplateOpcode::COUNT` steps of `1 << STEP_SIZE_LOG2` bytes, and `offset` is the
    // start of the step of an opcode, so less than that. It fits an `isize`, as the allocation
    // does.
    unsafe { interpreter(version).buffer.add(offset) }
}

pub(super) struct Interpreter {
    pub(super) buffer: *mut u8,
    /// The length of the code of each step, which is followed by padding to the size of the step.
    #[cfg(feature = "codegen-debug")]
    pub(super) step_lens: Box<[u8]>,
}

// SAFETY:
//
// Contract from `Send`: Types that can be transferred across thread boundaries.
//
// Evidence: `buffer` is the only field that is not `Send` itself. It points to the steps, which are
// read-execute and never freed once the `Interpreter` is constructed, so they can be used from any
// thread.
unsafe impl Send for Interpreter {}
// SAFETY:
//
// Contract from `Sync`: Types for which it is safe to share references between threads.
//
// Contract from `Sync`: The precise definition is: a type `T` is `Sync` if and only if `&T` is
// `Send`. In other words, if there is no possibility of undefined behavior (including data races)
// when passing `&T` references between threads.
//
// Evidence: `&Interpreter` only gives access to `buffer`, the address of memory that is never
// written to or freed once the `Interpreter` is constructed, and to `step_lens`, which is `Sync`,
// so there is nothing to race on.
unsafe impl Sync for Interpreter {}

/// Generates the interpreter.
///
/// This interpreter uses a dispatch table with one step of `1 << STEP_SIZE_LOG2` bytes per
/// `TemplateOpcode`, each running its instruction and then threading execution to the next one
/// directly, thus implementing a technique known as direct threading.
pub(super) struct InterpreterGenerator {
    buffer: *mut u8,
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
        self.buffer
    }

    fn new(version: SBPFVersion) -> Self {
        // Within the first 2 GiB, so that a backend may address it with absolute 32-bit addresses.
        let buffer = allocate_pages_low(Self::STEP_TABLE_SIZE)
            .expect("failed to allocate memory for the interpreter");
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
        assert!(self.offset.saturating_add(buffer.len()) <= Self::STEP_TABLE_SIZE);
        // SAFETY:
        //
        // Contract from `<*mut u8>::add`: The offset in bytes, `count * size_of::<T>()`, computed
        // on mathematical integers (without "wrapping around"), must fit in an `isize`.
        //
        // Contract from `<*mut u8>::add`: If the computed offset is non-zero, then `self` must be
        // derived from a pointer to some allocation, and the entire memory range between `self` and
        // the result must be in bounds of that allocation. In particular, this range must not "wrap
        // around" the edge of the address space.
        //
        // Evidence: `buffer` is the allocation of `allocate_pages_low` of `STEP_TABLE_SIZE` bytes,
        // and `offset` is at most `STEP_TABLE_SIZE`, per the assertion above. It fits an `isize`,
        // as the allocation does.
        let destination = unsafe { self.buffer.add(self.offset) };
        // SAFETY:
        //
        // Contract from `ptr::copy_nonoverlapping`: `src` must be valid for reads of `count *
        // size_of::<T>()` bytes or that number must be 0.
        //
        // Contract from `ptr::copy_nonoverlapping`: `dst` must be valid for writes of `count *
        // size_of::<T>()` bytes or that number must be 0.
        //
        // Contract from `ptr::copy_nonoverlapping`: Both `src` and `dst` must be properly aligned.
        //
        // Contract from `ptr::copy_nonoverlapping`: The region of memory beginning at `src` with a
        // size of `count * size_of::<T>()` bytes must *not* overlap with the region of memory
        // beginning at `dst` with the same size.
        //
        // Evidence: `T` is `u8`, so the pointers are aligned, and the size is `buffer.len()` bytes.
        // `buffer` is a slice, so valid for reads. The destination range ends within the
        // `STEP_TABLE_SIZE` bytes of the allocation at `buffer`, per the assertion above, which is
        // read-write until `generate_interpreter` protects it after the generation, and which
        // nothing else accesses meanwhile. `buffer` is not of that allocation, which only `self`
        // refers to, so the regions do not overlap.
        unsafe { std::ptr::copy_nonoverlapping(buffer.as_ptr(), destination, buffer.len()) };
        self.offset = self.offset.checked_add(buffer.len()).unwrap();
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
        let field = patch.range(0);
        // SAFETY:
        //
        // Contract from `<*mut u8>::add`: The offset in bytes, `count * size_of::<T>()`, computed
        // on mathematical integers (without "wrapping around"), must fit in an `isize`.
        //
        // Contract from `<*mut u8>::add`: If the computed offset is non-zero, then `self` must be
        // derived from a pointer to some allocation, and the entire memory range between `self` and
        // the result must be in bounds of that allocation. In particular, this range must not "wrap
        // around" the edge of the address space.
        //
        // Contract from `slice::from_raw_parts_mut`: `data` must be non-null, valid for both reads
        // and writes for `len * size_of::<T>()` many bytes, and it must be properly aligned. This
        // means in particular: The entire memory range of this slice must be contained within a
        // single allocation! Slices can never span across multiple allocations.
        //
        // Contract from `slice::from_raw_parts_mut`: `data` must point to `len` consecutive
        // properly initialized values of type `T`.
        //
        // Contract from `slice::from_raw_parts_mut`: The memory referenced by the returned slice
        // must not be accessed through any other pointer (not derived from the return value) for
        // the duration of lifetime `'a`. Both read and write accesses are forbidden.
        //
        // Contract from `slice::from_raw_parts_mut`: The total size `len * size_of::<T>()` of the
        // slice must be no larger than `isize::MAX`, and adding that size to `data` must not "wrap
        // around" the address space. See the safety documentation of `pointer::offset`.
        //
        // Evidence: `T` is `u8`, so the pointer is aligned, and the size is that of the field,
        // which is within the instruction that `extend` has just written into the
        // `STEP_TABLE_SIZE` bytes of the allocation of `allocate_pages_low` at `buffer`, so
        // the offset is within it and fits an `isize`. `generate_interpreter` filled the
        // allocation with `arch::TRAP_FILL`, so it is initialized, and it is read-write
        // until `generate_interpreter` protects it after the generation.
        // Nothing else accesses it while the slice lives, which ends at the end of this function.
        let field =
            unsafe { std::slice::from_raw_parts_mut(self.buffer.add(field.start), field.len()) };
        let target = target.wrapping_sub(self.buffer as usize);
        patch
            .patch(field, self.buffer as usize, target)
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

    fn bpf_taken_branch(&mut self) {
        arch::interpreter_taken_branch(self);
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
    let mut generator = InterpreterGenerator::new(version);
    #[cfg(all(feature = "codegen-debug", target_os = "linux"))]
    // SAFETY:
    //
    // Contract from `CodeRecord::new`: The `len` bytes at `start` must be pages of a mapping that
    // the caller owns.
    //
    // Contract from `CodeRecord::new`: Nothing may access these pages while this runs, or rely on
    // what they held before: they are replaced with a mapping that stays until `release`.
    //
    // Evidence: the range is the allocation of `allocate_pages_low` of `STEP_TABLE_SIZE` bytes,
    // which `generator` just made, and which nothing else refers to. Nothing was written to it yet,
    // and the steps are generated into it afterwards. The mapping stays, as the interpreter is
    // never freed.
    let code_record = unsafe {
        super::debug::CodeRecord::new(
            &format!("interpreter-{version:?}").to_lowercase(),
            generator.buffer as usize,
            InterpreterGenerator::STEP_TABLE_SIZE,
        )
    };
    // The space after the code of a step traps if it is ever executed.
    //
    // SAFETY:
    //
    // Contract from `ptr::write_bytes`: `dst` must be valid for writes of `count * size_of::<T>()`
    // bytes.
    //
    // Contract from `ptr::write_bytes`: `dst` must be properly aligned.
    //
    // Evidence: `T` is `u8`, so the pointer is aligned, and the size is `STEP_TABLE_SIZE` bytes,
    // which is the read-write allocation of `allocate_pages_low` at `generator.buffer`. Nothing
    // else accesses it meanwhile.
    unsafe {
        std::ptr::write_bytes(
            generator.buffer,
            arch::TRAP_FILL,
            InterpreterGenerator::STEP_TABLE_SIZE,
        )
    };
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
        // SAFETY:
        //
        // Contract from `<*mut u8>::add`: The offset in bytes, `count * size_of::<T>()`, computed
        // on mathematical integers (without "wrapping around"), must fit in an `isize`.
        //
        // Contract from `<*mut u8>::add`: If the computed offset is non-zero, then `self` must be
        // derived from a pointer to some allocation, and the entire memory range between `self` and
        // the result must be in bounds of that allocation. In particular, this range must not "wrap
        // around" the edge of the address space.
        //
        // Contract from `slice::from_raw_parts_mut`: `data` must be non-null, valid for both reads
        // and writes for `len * size_of::<T>()` many bytes, and it must be properly aligned. This
        // means in particular: The entire memory range of this slice must be contained within a
        // single allocation! Slices can never span across multiple allocations.
        //
        // Contract from `slice::from_raw_parts_mut`: `data` must point to `len` consecutive
        // properly initialized values of type `T`.
        //
        // Contract from `slice::from_raw_parts_mut`: The memory referenced by the returned slice
        // must not be accessed through any other pointer (not derived from the return value) for
        // the duration of lifetime `'a`. Both read and write accesses are forbidden.
        //
        // Contract from `slice::from_raw_parts_mut`: The total size `len * size_of::<T>()` of the
        // slice must be no larger than `isize::MAX`, and adding that size to `data` must not "wrap
        // around" the address space. See the safety documentation of `pointer::offset`.
        //
        // Evidence: `T` is `u8`, so the pointer is aligned, and the size is `step_len` bytes. The
        // step is within the `STEP_TABLE_SIZE` bytes of the allocation of `allocate_pages_low` at
        // `generator.buffer`, as `extend` asserts for the code written into it, so the offset is
        // within it and fits an `isize`. It is initialized, as the allocation was filled with
        // `arch::TRAP_FILL` above, and it is read-write until it is protected below. Nothing else
        // accesses it while the slice lives, which ends with `resolve`.
        let step =
            unsafe { std::slice::from_raw_parts_mut(generator.buffer.add(step_start), step_len) };
        generator.relocs.resolve(step, step_start);
        #[cfg(feature = "codegen-debug")]
        {
            step_lens[opcode.index()] = step_len.try_into().unwrap();
        }
    }

    #[cfg(feature = "codegen-debug")]
    let step_lens = step_lens.into_boxed_slice();
    #[cfg(all(feature = "codegen-debug", target_os = "linux"))]
    super::debug::finish_interpreter(code_record, version, generator.buffer, &step_lens);

    // SAFETY:
    //
    // Contract from `protect_pages`: These pages must be of an allocation that the caller owns.
    //
    // Contract from `protect_pages`: While `permissions` apply, nothing may access these pages in a
    // way that `permissions` do not allow.
    //
    // Evidence: the pages are the allocation of `allocate_pages_low` of `STEP_TABLE_SIZE` bytes,
    // which `generator` made, and which the interpreter keeps forever. The steps are only executed,
    // and read by `codegen::debug`, afterwards.
    unsafe {
        protect_pages(
            generator.buffer,
            InterpreterGenerator::STEP_TABLE_SIZE,
            PagePermissions::ReadExecute,
        )
    }
    .expect("failed to make the interpreter executable");
    Interpreter {
        buffer: generator.buffer,
        #[cfg(feature = "codegen-debug")]
        step_lens,
    }
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
                .any(|layout| usize::from(layout.num_relocations) == MAX_RELOCATIONS));
        }
    }
}

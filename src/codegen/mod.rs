//! Unified JIT and interpreted execution of BPF code.
//!
//! TODO: write some design philosphies here.

// Everything here is used by the architecture specific backends, of which there may be none.
#![cfg_attr(not(target_arch = "x86_64"), allow(dead_code, unused_imports))]

#[cfg(target_arch = "x86_64")]
pub mod x64;

use crate::ebpf;
use crate::elf::Executable;
use crate::error::{EbpfError, ProgramResult};
pub use crate::program::JitProgram;
use crate::program::SBPFVersion;
use crate::vm::{ContextObject, EbpfVm};
use dynasmrt::components::{LabelRegistry, PatchLoc, RelocRegistry};
use dynasmrt::relocations::{Relocation, RelocationKind};
use dynasmrt::{AssemblyOffset, DynamicLabel};
use rand::rngs::SmallRng;
use rand::{thread_rng, Rng, RngCore, SeedableRng};
use std::convert::{TryFrom, TryInto};
use std::num::NonZeroU64;

/// Size of the instruction with the opcode `op`, in bytes.
const fn insn_size(op: u8) -> usize {
    if op == ebpf::LD_DW_IMM {
        2 * ebpf::INSN_SIZE
    } else {
        ebpf::INSN_SIZE
    }
}

const SIG_INVALID_INSN: i8 = -1;
const SIG_EXCEEDED_MAX_INSTRUCTIONS: i8 = -2;
const SIG_CALL_DEPTH_EXCEEDED: i8 = -3;
const SIG_DIVIDE_BY_ZERO: i8 = -4;
const SIG_EXECUTION_OVERRUN: i8 = -5;
const SIG_CALL_OUTSIDE_TEXT_SEGMENT: i8 = -6;
/// `vm.program_result` has already been set.
const SIG_PROGRAM_RESULT: i8 = -7;

/// The initial value of `meter` for executing `bpf` from `vm.registers[11]` with
/// `vm.previous_instruction_meter` as the budget: the address of the instruction following the
/// last one that is within budget.
fn initial_meter<C: ContextObject>(bpf: &[u8], vm: &EbpfVm<C>) -> u64 {
    let pc = vm.registers[11];
    let budget = vm.previous_instruction_meter;
    assert!(
        budget <= u32::MAX as u64,
        "the instruction budget is nonsensical"
    );
    (bpf.as_ptr() as u64).wrapping_add(pc.wrapping_add(budget).wrapping_mul(ebpf::INSN_SIZE as u64))
}

/// Finalize `vm` fields after the generated code has terminated with `code`.
fn finish_execution<C: ContextObject>(
    vm: &mut EbpfVm<C>,
    exit_code: i8,
    meter: u64,
    r0: u64,
    last_pc: u64,
) {
    vm.registers[11] = last_pc.wrapping_sub(1);
    let remaining = if exit_code == SIG_EXCEEDED_MAX_INSTRUCTIONS || (meter as i64) < 0 {
        0
    } else {
        meter / const { NonZeroU64::new(ebpf::INSN_SIZE as u64).unwrap() }
    };
    // Syscalls consume the budget used up to them and update `previous_instruction_meter`.
    vm.due_insn_count = vm.previous_instruction_meter.saturating_sub(remaining);
    use EbpfError::*;
    match exit_code {
        0 => vm.program_result = ProgramResult::Ok(r0),
        // Calls into Rust store their errors into `vm.program_result` themselves.
        SIG_PROGRAM_RESULT => {}
        SIG_EXCEEDED_MAX_INSTRUCTIONS => {
            vm.program_result = ProgramResult::Err(ExceededMaxInstructions)
        }
        SIG_INVALID_INSN => vm.program_result = ProgramResult::Err(UnsupportedInstruction),
        SIG_CALL_DEPTH_EXCEEDED => vm.program_result = ProgramResult::Err(CallDepthExceeded),
        SIG_DIVIDE_BY_ZERO => vm.program_result = ProgramResult::Err(DivideByZero),
        SIG_EXECUTION_OVERRUN => vm.program_result = ProgramResult::Err(ExecutionOverrun),
        SIG_CALL_OUTSIDE_TEXT_SEGMENT => {
            vm.program_result = ProgramResult::Err(CallOutsideTextSegment)
        }
        _ => unreachable!("unexpected exit code {}", exit_code),
    }
}

#[cfg(target_arch = "x86_64")]
/// Interpret `executable`, starting at `vm.registers[11]`.
pub fn interpret<C: ContextObject>(executable: &Executable<C>, vm: &mut EbpfVm<C>) {
    x64::enter(executable, None, vm)
}

impl JitProgram {
    #[cfg(target_arch = "x86_64")]
    pub(crate) fn dynasm_invoke<C: ContextObject>(
        &self,
        executable: &Executable<C>,
        vm: &mut EbpfVm<C>,
    ) {
        x64::enter(
            executable,
            Some((self.pc_section(), self.text_section().as_ptr())),
            vm,
        )
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum MemoryAccessKind {
    Load,
    StoreImm,
    StoreReg,
}

/// A BPF register.
#[derive(Clone, Copy, PartialEq, Eq)]
struct Reg(u8);

impl Reg {
    /// The number of the BPF registers.
    const COUNT: usize = 11;
    const ALL: [Reg; Self::COUNT] = const {
        let mut out = [Reg(0); Self::COUNT];
        let mut i = 0;
        while i < Self::COUNT {
            out[i] = Reg(i as u8);
            i += 1;
        }
        out
    };

    /// `None` if there's no such register.
    const fn new(number: u8) -> Option<Self> {
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
struct TemplateOpcode(u16);

impl TemplateOpcode {
    const COUNT: usize = 1 + u16::MAX as usize;
    /// Of the instruction `insn`.
    const fn of(insn: u64) -> Self {
        Self(insn as u16)
    }
    /// Iterator over all instructions in order of the dispatch table.
    fn all() -> impl Iterator<Item = Self> {
        (0..=u16::MAX).map(Self)
    }
    const fn index(self) -> usize {
        self.0 as usize
    }
    const fn op(self) -> u8 {
        self.0 as u8
    }
    /// The destination register field.
    const fn dst(self) -> Option<Reg> {
        Reg::new((self.0 >> 8 & 0xf) as u8)
    }
    /// The source register field.
    const fn src(self) -> Option<Reg> {
        Reg::new((self.0 >> 12) as u8)
    }
}

/// Every template reserves this many relocations, so keep it at the maximum that any template
/// needs (`templates_fit_max_relocations` checks both directions).
/// The tracer's prelude takes another one.
const MAX_RELOCATIONS: usize = if cfg!(feature = "tracer") { 4 } else { 3 };

/// Generates a template into the parts of `JitTemplates`.
struct TemplateBuilder<'a, const SIZE: usize> {
    layout: &'a mut TemplateLayout,
    code: &'a mut [u8; SIZE],
    relocations: &'a mut [TemplateRelocation; MAX_RELOCATIONS],
}

impl<const SIZE: usize> TemplateBuilder<'_, SIZE> {
    fn code_mut(&mut self) -> &mut [u8] {
        &mut self.code[..self.layout.len()]
    }

    fn add_relocation(&mut self, relocation: TemplateRelocation) {
        let slot = self
            .relocations
            .get_mut(usize::from(self.layout.num_relocations))
            .expect("template needs more relocations than MAX_RELOCATIONS");
        *slot = relocation;
        self.layout.num_relocations = self.layout.num_relocations.checked_add(1).unwrap();
    }

    #[track_caller]
    fn extend(&mut self, buffer: &[u8]) {
        for &byte in buffer {
            self.push(byte);
        }
    }

    fn offset(&self) -> usize {
        self.layout.len()
    }

    #[track_caller]
    fn push(&mut self, byte: u8) {
        self.code[self.layout.len()] = byte;
        self.layout.bytes = self.layout.bytes.checked_add(1).unwrap();
    }
}

/// Relocations against dynamic labels defined within the code being generated.
///
/// These are resolved as soon as the code generation completes: for JIT that's when the template
/// is finalized, for the interpreter that's once all the steps have been generated.
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

    /// Patch all the recorded relocations into `buffer` and reset the label state.
    ///
    /// `buf_addr` is the address at which `buffer` will reside during execution. `None` means
    /// that the code is position independent and will get copied elsewhere, in which case only the
    /// relative relocations are supported.
    fn resolve(&mut self, buffer: &mut [u8], buf_addr: Option<usize>) {
        for (loc, id) in self.relocs.take_dynamics() {
            if buf_addr.is_none() {
                assert!(
                    matches!(loc.relocation.kind(), RelocationKind::Relative),
                    "position independent code may only contain relative label references"
                );
            }
            let target = self.labels.resolve_dynamic(id).unwrap();
            let range = loc.range(0);
            loc.patch(&mut buffer[range], buf_addr.unwrap_or(0), target.0)
                .expect("impossible relocation");
        }
        self.labels.clear();
    }
}

/// Relocation parameters as produced by `dynasm`, sans the location.
#[derive(Clone, Copy)]
struct PatchFields<R> {
    target_offset: isize,
    field_offset: u8,
    ref_offset: u8,
    relocation: R,
}

impl<R: Relocation + Copy> PatchFields<R> {
    fn new(target_offset: isize, field_offset: u8, ref_offset: u8, kind: u8) -> Self {
        Self {
            target_offset,
            field_offset,
            ref_offset,
            relocation: R::from_encoding(kind),
        }
    }

    /// `at` is the offset right past the instruction containing the field to patch (i.e. the
    /// offset at the time `dynasm` reports the relocation.)
    fn at(self, at: usize) -> PatchLoc<R> {
        PatchLoc::new(
            AssemblyOffset(at),
            self.target_offset,
            self.field_offset,
            self.ref_offset,
            self.relocation,
        )
    }
}

#[derive(Clone, Copy, Debug)]
enum TemplateRelocationKind {
    /// The JIT holds a pointer to the second instruction of the eBPF program in `insn`,
    /// whereas the templates default to addressing where `insn` is updated to point to right
    /// after the current instruction. This relocation adds the offset of the current instruction
    /// to the field.
    InsnOffset,
    /// When BPF instruction represents a branch, and the branch is taken, the control flow has to
    /// transfer to the machine code representing the target BPF instruction's code. Offset to this
    /// machine code is what this relocation must overwrite based on the BPF instruction being
    /// templated.
    TakenBranch,
    /// Offset (in bytes) from the instruction following the branch to the branch target.
    TakenBranchMeterAdjustment,
}

/// A relocation that can only be resolved once the template is instantiated for a specific eBPF
/// instruction at a specific location: a 32-bit field in the template, set to the target of the
/// relocation plus `addend`.
#[derive(Clone, Copy, Debug)]
struct TemplateRelocation {
    /// Offset of the field within the template.
    field: u8,
    /// For relative relocations, this already accounts for where the field is in the template,
    /// but not for where the template is in the output.
    addend: i32,
    kind: TemplateRelocationKind,
}

impl TemplateRelocation {
    /// For the unused entries, which `JitTemplates::emit` does not apply.
    const UNUSED: Self = Self {
        field: 0,
        addend: 0,
        kind: TemplateRelocationKind::InsnOffset,
    };

    /// `patch` is a relocation reported by `dynasm` at `location` within the template.
    fn new<R: Relocation>(
        kind: TemplateRelocationKind,
        location: usize,
        patch: PatchFields<R>,
    ) -> Self {
        let relative = match kind {
            TemplateRelocationKind::TakenBranch => true,
            TemplateRelocationKind::InsnOffset
            | TemplateRelocationKind::TakenBranchMeterAdjustment => false,
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
        Self {
            field: u8::try_from(field).unwrap(),
            addend: i32::try_from(patch.target_offset.checked_sub(reference as isize).unwrap())
                .unwrap(),
            kind,
        }
    }

    /// Patch the relocation into `template`, instantiated for the instruction `insn` at `pc`, at
    /// `template_start` in the output.
    #[inline(always)]
    fn apply<const SIZE: usize>(
        &self,
        template: &mut [u8; SIZE],
        template_start: usize,
        pc: usize,
        insn: u64,
        pc_section: &[u32],
    ) {
        // Computed in `i64`, to which all the inputs convert losslessly, and in which none of the
        // arithmetic below can overflow: `template_start` is below `NOOP_DUE` (see `analyze`), as
        // are the `pc_section` entries, `pc * INSN_SIZE` is an offset into the text section, and
        // `off` and `addend` are at most 32 bits.
        let off = (insn >> 16) as i16;
        let target = match self.kind {
            TemplateRelocationKind::InsnOffset => (pc as i64).wrapping_mul(ebpf::INSN_SIZE as i64),
            TemplateRelocationKind::TakenBranchMeterAdjustment => {
                i64::from(off).wrapping_mul(ebpf::INSN_SIZE as i64)
            }
            TemplateRelocationKind::TakenBranch => {
                // The verifier rejects invalid jump offsets, but doing this defensive thing is
                // faster anyway.
                let target = pc
                    .checked_add_signed(isize::from(off).wrapping_add(1))
                    .and_then(|target_pc| pc_section.get(target_pc))
                    .copied()
                    .unwrap_or(JitTemplates::<SIZE>::INVALID_JUMP_TARGET);
                i64::from(target & !PADDING_DUE).wrapping_sub(template_start as i64)
            }
        };
        let value = target.wrapping_add(i64::from(self.addend));
        debug_assert!(i32::try_from(value).is_ok(), "impossible relocation");
        // Never clamps (see `new`), but `min` elides a bounds check.
        let max_field = const { SIZE - 4 };
        debug_assert!(usize::from(self.field) <= max_field);
        let field = usize::from(self.field).min(max_field);
        template[field..field.wrapping_add(4)].copy_from_slice(&(value as i32).to_le_bytes());
    }
}

/// What the first pass of `JitTemplates::compile` needs to know of a template, apart from the
/// machine code and the relocations.
#[derive(Clone, Copy, Debug)]
struct TemplateLayout {
    /// Length of the machine code.
    bytes: u8,
    num_relocations: u8,
    /// Size of the BPF instruction this template is for, minus one.
    ///
    /// LD_DW_IMM template holds a 1, all others 0.
    extra_bpf_insns: u8,
    /// Does the code check the instruction meter (with the budget of the instruction itself)?
    checks_meter: bool,
}

impl TemplateLayout {
    /// Length of the machine code.
    fn len(self) -> usize {
        usize::from(self.bytes)
    }
}

/// The JIT templates other than for the instructions.
#[derive(Clone, Copy)]
#[repr(u8)]
enum AuxTemplate {
    /// Appended after the last instruction, as if it was at `pc = program.len()`.
    ExecutionOverrun,
    /// For `pc_section` entries that are not valid jump targets (e.g. the second halves of 16
    /// byte instructions.)
    InvalidJumpTarget,
    /// Inserted between the other templates to diversify the output.
    Noop,
    /// Inserted ahead of an instruction (and instantiated for it) to check the instruction meter.
    MeterCheckpoint,
}

impl AuxTemplate {
    const COUNT: usize = 4;
    /// Index within `JitTemplates`.
    const fn index(self) -> usize {
        TemplateOpcode::COUNT.wrapping_add(self as usize)
    }
}

const NUM_TEMPLATES: usize = TemplateOpcode::COUNT + AuxTemplate::COUNT;

/// Machine code templates the JIT output is assembled from.
///
/// Split up, so that the first pass of `compile` only touches the layouts.
pub struct JitTemplates<const SIZE: usize> {
    layouts: Box<[TemplateLayout; NUM_TEMPLATES]>,
    code: Box<[[u8; SIZE]; NUM_TEMPLATES]>,
    relocations: Box<[[TemplateRelocation; MAX_RELOCATIONS]; NUM_TEMPLATES]>,
}

/// A bitflag set in `pc_section` by `JitTemplates::analyze` for the instructions that include a
/// checkpoint.
const CHECKPOINT_DUE: u32 = 1 << 31;
/// Likewise for a no-op ahead of the instruction.
const NOOP_DUE: u32 = 1 << 30;
const PADDING_DUE: u32 = CHECKPOINT_DUE | NOOP_DUE;
/// Longest run of no-ops `JitTemplates::compile` may insert at the beginning.
const MAX_START_PADDING_LENGTH: usize = 256;

impl<const SIZE: usize> JitTemplates<SIZE> {
    /// Offset of the `AuxTemplate::InvalidJumpTarget` in the output, which is emitted first.
    const INVALID_JUMP_TARGET: u32 = 0;

    fn empty() -> Self {
        let layout = TemplateLayout {
            bytes: 0,
            num_relocations: 0,
            extra_bpf_insns: 0,
            checks_meter: false,
        };
        const { assert!(SIZE <= u8::MAX as usize) };
        Self {
            layouts: vec![layout; NUM_TEMPLATES]
                .into_boxed_slice()
                .try_into()
                .unwrap(),
            code: vec![[0; SIZE]; NUM_TEMPLATES]
                .into_boxed_slice()
                .try_into()
                .unwrap(),
            relocations: vec![[TemplateRelocation::UNUSED; MAX_RELOCATIONS]; NUM_TEMPLATES]
                .into_boxed_slice()
                .try_into()
                .unwrap(),
        }
    }

    fn builder(&mut self, index: usize) -> TemplateBuilder<'_, SIZE> {
        TemplateBuilder {
            layout: &mut self.layouts[index],
            code: &mut self.code[index],
            relocations: &mut self.relocations[index],
        }
    }

    fn insn_builder(&mut self, opcode: TemplateOpcode) -> TemplateBuilder<'_, SIZE> {
        self.builder(opcode.index())
    }

    fn aux_builder(&mut self, template: AuxTemplate) -> TemplateBuilder<'_, SIZE> {
        self.builder(template.index())
    }

    /// First pass analysis of the program to be compiled.
    ///
    /// This gathers the offsets at which corresponding instructions would have their machine code
    /// placed.
    fn analyze<C: ContextObject>(&self, executable: &Executable<C>) -> (Vec<u32>, usize, usize) {
        let bpf = executable.get_text_bytes().1;
        let config = executable.get_config();
        let noop_instruction_rate = config.noop_instruction_rate;
        let instruction_meter_checkpoint_distance = config.instruction_meter_checkpoint_distance;
        let (program, rest) = bpf.as_chunks::<{ ebpf::INSN_SIZE }>();
        assert!(rest.is_empty());
        // The no-ops diversify the output to make the locations of specific code slightly less
        // predictable.
        // FIXME: Unlike the old JIT, which counts the host instructions, the rate counts the
        // BPF instructions, so there are fewer no-ops inserted for the same rate.
        let mut rng =
            SmallRng::from_rng(thread_rng()).expect("failed to seed the JIT diversification");
        let noop_threshold = u32::MAX.checked_div(noop_instruction_rate).unwrap_or(0);
        let start_padding = rng
            .gen_range(0..MAX_START_PADDING_LENGTH)
            .wrapping_mul((noop_threshold != 0) as usize);

        // `position` saturates so that an absurdly large output fails the check at the end.
        let mut pc_sec = Vec::with_capacity(program.len());
        let mut position = 0usize;
        position = position.wrapping_add(self.aux_layout(AuxTemplate::InvalidJumpTarget).len());
        position = position
            .wrapping_add(start_padding.wrapping_mul(self.aux_layout(AuxTemplate::Noop).len()));
        // Introduce checkpoints at certain points in the code; the instruction meter is otherwise
        // only checked on control flow, so straight-line code could run arbitrarily far past the
        // budget.
        let mut until_checkpoint = instruction_meter_checkpoint_distance;
        let mut program_iter = program.iter();
        while let Some(insn) = program_iter.next() {
            let insn = u64::from_le_bytes(*insn);
            let layout = self.insn_layout(TemplateOpcode::of(insn));
            let noop = if rng.next_u32() < noop_threshold {
                position = position.wrapping_add(self.aux_layout(AuxTemplate::Noop).len());
                NOOP_DUE
            } else {
                0
            };
            let checkpoint = if layout.checks_meter {
                until_checkpoint = instruction_meter_checkpoint_distance;
                0
            } else if until_checkpoint == 0 {
                until_checkpoint = instruction_meter_checkpoint_distance;
                position =
                    position.wrapping_add(self.aux_layout(AuxTemplate::MeterCheckpoint).len());
                CHECKPOINT_DUE
            } else {
                // Not zero in this branch.
                until_checkpoint = until_checkpoint.wrapping_sub(1);
                0
            };
            // Truncation is ruled out below, once the final `position` is known.
            pc_sec.push(position as u32 | noop | checkpoint);
            position = position.wrapping_add(layout.len());
            for _ in 0..layout.extra_bpf_insns {
                program_iter.next();
                pc_sec.push(Self::INVALID_JUMP_TARGET);
            }
        }
        position = position.wrapping_add(self.aux_layout(AuxTemplate::ExecutionOverrun).len());
        assert!(position < NOOP_DUE as usize, "JIT output too large");
        (pc_sec, position, start_padding)
    }

    /// Compile the text section of `executable` into machine code.
    ///
    /// Due to the time sensitive nature of this code we try to do minimal amount of work here.
    /// The result is a two pass algorithm where the first pass determines ahead of time where
    /// each instruction's machine code will be, allowing for e.g. forward jump relocations to be
    /// resolved immediately during the emission.
    pub fn compile<C: ContextObject>(
        &self,
        executable: &Executable<C>,
    ) -> Result<JitProgram, EbpfError> {
        let (mut pc_sec, output_len, start_padding) = self.analyze(executable);
        // Templates are always written out in large chunks to employ SIMD and avoid memcpy calls,
        // so the last one may extend past the output.
        // `output_len` is below `NOOP_DUE`, see `analyze`, and the sizes are far from `usize::MAX`.
        let mut program = JitProgram::new(pc_sec.len(), output_len.wrapping_add(SIZE));
        program.dynasm = true;

        let mut position = 0;
        let text = program.text_section_mut();
        self.emit_aux(
            text,
            &mut position,
            &pc_sec,
            0,
            AuxTemplate::InvalidJumpTarget,
        );
        for _ in 0..start_padding {
            self.emit_aux(text, &mut position, &pc_sec, 0, AuxTemplate::Noop);
        }

        let bpf = executable.get_text_bytes().1;
        let (program_insns, _) = bpf.as_chunks::<{ ebpf::INSN_SIZE }>();
        let mut program_iter = program_insns.iter().zip(&pc_sec).enumerate();
        while let Some((pc, (insn, &entry))) = program_iter.next() {
            let insn = u64::from_le_bytes(*insn);
            let opcode = TemplateOpcode::of(insn);
            for _ in 0..self.insn_layout(opcode).extra_bpf_insns {
                program_iter.next();
            }
            if entry & PADDING_DUE != 0 {
                if entry & NOOP_DUE != 0 {
                    self.emit_aux(text, &mut position, &pc_sec, pc, AuxTemplate::Noop);
                }
                if entry & CHECKPOINT_DUE != 0 {
                    self.emit_aux(
                        text,
                        &mut position,
                        &pc_sec,
                        pc,
                        AuxTemplate::MeterCheckpoint,
                    );
                }
            }
            self.emit(text, &mut position, &pc_sec, pc, insn, opcode.index());
        }
        let pc = program_insns.len();
        self.emit_aux(
            text,
            &mut position,
            &pc_sec,
            pc,
            AuxTemplate::ExecutionOverrun,
        );
        debug_assert_eq!(position, output_len);
        for entry in &mut pc_sec {
            *entry &= !PADDING_DUE;
        }
        // The emission looks the jump targets up in the `Vec`, which is also the only place
        // the flags are in; it is small next to the machine code, so the copy is cheap.
        program.pc_section_mut().copy_from_slice(&pc_sec);
        program.seal(output_len)?;
        Ok(program)
    }

    fn insn_layout(&self, opcode: TemplateOpcode) -> TemplateLayout {
        self.layouts[opcode.index()]
    }

    fn aux_layout(&self, template: AuxTemplate) -> TemplateLayout {
        self.layouts[template.index()]
    }

    /// Write the `template` instantiated for `pc` at `position` in `text`, see `emit`.
    #[inline(always)]
    fn emit_aux(
        &self,
        text: &mut [u8],
        position: &mut usize,
        pc_section: &[u32],
        pc: usize,
        template: AuxTemplate,
    ) {
        self.emit(text, position, pc_section, pc, 0, template.index());
    }

    /// Write the template at `index` instantiated for the instruction `insn` at `pc` at `position`
    /// in `text`, and advance `position` past it.
    ///
    /// `text` must have at least `SIZE` bytes from `position` on.
    #[inline(always)]
    fn emit(
        &self,
        text: &mut [u8],
        position: &mut usize,
        pc_section: &[u32],
        pc: usize,
        insn: u64,
        index: usize,
    ) {
        let layout = self.layouts[index];
        let len = layout.len();
        let start = *position;
        let out = text
            .get_mut(start..)
            .and_then(|rest| rest.first_chunk_mut::<SIZE>())
            .expect("JIT output size miscalculated!");
        // Most of the templates are short, so they only get the first (fixed size) copy. The two
        // copies are disjoint so that they do not get merged into a single variable size memcpy.
        const SHORT: usize = 16;
        const { assert!(SIZE >= SHORT) };
        let (out_short, out_rest) = out.split_at_mut(SHORT);
        let (short, rest) = self.code[index].split_at(SHORT);
        out_short.copy_from_slice(short);
        if len > SHORT {
            out_rest.copy_from_slice(rest);
        }
        let relocations = &self.relocations[index][..usize::from(layout.num_relocations)];
        for relocation in relocations {
            relocation.apply(out, start, pc, insn, pc_section);
        }
        *position = start.wrapping_add(len);
    }
}

#[cfg(all(feature = "codegen_debug", target_os = "linux"))]
/// Add `code`, which runs from `address`, called `name` to the perf jitdump
/// (`/tmp/jit-<pid>.dump`).
fn write_perf_jitdump(name: &str, address: *const u8, code: &[u8], elf_machine: u32) {
    use std::io::Write as _;
    use std::os::fd::AsRawFd as _;
    use std::sync::{Mutex, OnceLock};

    fn now() -> u64 {
        let mut ts = libc::timespec {
            tv_sec: 0,
            tv_nsec: 0,
        };
        // SAFETY:
        //
        // Contract from `clock_gettime`: the pointer must be valid for writing a `timespec`.
        // Evidence: it points at the local `ts`.
        unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut ts) };
        (ts.tv_sec as u64)
            .wrapping_mul(1_000_000_000)
            .wrapping_add(ts.tv_nsec as u64)
    }

    // The header is only written once, then each of the code regions is a record of the same file,
    // and its index is the number of records before.
    static JITDUMP: OnceLock<Mutex<(std::fs::File, u64)>> = OnceLock::new();
    let pid = std::process::id();
    // SAFETY:
    //
    // Contract from `syscall`: the arguments must be what the system call expects.
    // Evidence: `gettid` takes none.
    let tid = unsafe { libc::syscall(libc::SYS_gettid) } as u32;

    let dump = JITDUMP.get_or_init(|| {
        let mut f = std::fs::File::create(format!("/tmp/jit-{pid}.dump")).unwrap();
        // 1. JIT Header (40 bytes)
        f.write_all(&0x4A495444u32.to_le_bytes()).unwrap(); // Magic: "JITD"
        f.write_all(&1u32.to_le_bytes()).unwrap(); // Version
        f.write_all(&40u32.to_le_bytes()).unwrap(); // Header size
        f.write_all(&elf_machine.to_le_bytes()).unwrap();
        f.write_all(&0u32.to_le_bytes()).unwrap(); // Pad
        f.write_all(&pid.to_le_bytes()).unwrap();
        f.write_all(&now().to_le_bytes()).unwrap();
        f.write_all(&0u64.to_le_bytes()).unwrap(); // Flags

        // Triggers perf record's MMAP detection
        //
        // SAFETY:
        //
        // Contract from `mmap`: without `MAP_FIXED` it may not replace existing mappings, and the
        // file descriptor must be open.
        // Evidence: the hint is null and no flags beyond `MAP_PRIVATE` are given, and `f` is open.
        let m = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                4096,
                libc::PROT_READ | libc::PROT_EXEC,
                libc::MAP_PRIVATE,
                f.as_raw_fd(),
                0,
            )
        };
        if m != libc::MAP_FAILED {
            // SAFETY:
            //
            // Contract from `munmap`: nothing may access the range afterwards.
            // Evidence: it is exactly the mapping just created, which nothing references.
            unsafe { libc::munmap(m, 4096) };
        }
        Mutex::new((f, 0))
    });
    let (f, records) = &mut *dump.lock().unwrap();

    // 2. JIT_CODE_LOAD Record Header (56 bytes, then the name and its NUL)
    let rec_size = 56usize
        .wrapping_add(name.len())
        .wrapping_add(1)
        .wrapping_add(code.len()) as u32;
    f.write_all(&0u32.to_le_bytes()).unwrap(); // ID: JIT_CODE_LOAD
    f.write_all(&rec_size.to_le_bytes()).unwrap();
    f.write_all(&now().to_le_bytes()).unwrap();
    f.write_all(&pid.to_le_bytes()).unwrap();
    f.write_all(&tid.to_le_bytes()).unwrap();
    f.write_all(&(address as u64).to_le_bytes()).unwrap(); // VMA
    f.write_all(&(address as u64).to_le_bytes()).unwrap(); // Code Address
    f.write_all(&(code.len() as u64).to_le_bytes()).unwrap(); // Code Size
    f.write_all(&records.wrapping_add(1).to_le_bytes()).unwrap(); // Index
    f.write_all(name.as_bytes()).unwrap();
    f.write_all(&[0]).unwrap();
    *records = records.wrapping_add(1);

    // 3. Raw Code Bytes
    f.write_all(code).unwrap();
}

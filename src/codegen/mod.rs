// Everything here is used by the architecture specific backends, of which there may be none.
#![cfg_attr(not(target_arch = "x86_64"), allow(dead_code, unused_imports))]

#[cfg(target_arch = "x86_64")]
pub mod x64;

use crate::ebpf;
use crate::elf::Executable;
use crate::error::{EbpfError, ProgramResult};
use crate::program::SBPFVersion;
use crate::vm::{ContextObject, EbpfVm};
use dynasmrt::components::{LabelRegistry, PatchLoc, RelocRegistry};
use dynasmrt::relocations::{Relocation, RelocationKind};
use dynasmrt::{AssemblyOffset, DynamicLabel};
use rand::rngs::SmallRng;
use rand::{thread_rng, Rng, RngCore, SeedableRng};
use std::convert::{TryFrom, TryInto};
use std::mem::MaybeUninit;

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

/// Update `vm` after the generated code has terminated with `code`, leaving `meter` behind.
// FIXME: this does not store the final pc into `vm.registers[11]`, which the old JIT does: the pc
// of the `exit`, or of the instruction that failed.
fn finish_execution<C: ContextObject>(vm: &mut EbpfVm<C>, code: i8, meter: u64) {
    let remaining = if code == SIG_EXCEEDED_MAX_INSTRUCTIONS || (meter as i64) < 0 {
        0
    } else {
        meter / ebpf::INSN_SIZE as u64
    };
    // Syscalls consume the budget used up to them and update `previous_instruction_meter`.
    vm.due_insn_count = vm.previous_instruction_meter.saturating_sub(remaining);
    use EbpfError::*;
    match code {
        0 => vm.program_result = ProgramResult::Ok(vm.registers[0]),
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
        _ => unreachable!("unexpected exit code {}", code),
    }
}

#[cfg(target_arch = "x86_64")]
/// Compile `executable` and execute it, starting at `vm.registers[11]`.
pub fn jit_and_run<C: ContextObject>(executable: &Executable<C>, vm: &mut EbpfVm<C>) {
    let program = x64::jit_templates(executable.get_sbpf_version()).compile(executable);
    let code = &program.text_section;
    let mut buffer = dynasmrt::mmap::MutableBuffer::new(code.len())
        .expect("failed to allocate executable memory for the JIT output");
    buffer.set_len(code.len());
    buffer.copy_from_slice(code);
    let buffer = buffer
        .make_exec()
        .expect("failed to make the JIT output executable");
    x64::enter(executable, Some((&program.pc_section, buffer.as_ptr())), vm)
}

#[cfg(target_arch = "x86_64")]
/// Interpret `executable`, starting at `vm.registers[11]`.
pub fn interpret_and_run<C: ContextObject>(executable: &Executable<C>, vm: &mut EbpfVm<C>) {
    x64::enter(executable, None, vm)
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

const MAX_RELOCATIONS: usize = 8;

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
        self.relocations[usize::from(self.layout.num_relocations)] = relocation;
        self.layout.num_relocations += 1;
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
        self.layout.bytes += 1;
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
            location - usize::from(patch.ref_offset)
        } else {
            0
        };
        let field = location - usize::from(patch.field_offset);
        // The template ends no earlier than `location`, so the field is within it. `apply` relies
        // on this.
        assert!(field + 4 <= location, "unsupported template relocation");
        Self {
            field: u8::try_from(field).unwrap(),
            addend: i32::try_from(patch.target_offset - reference as isize).unwrap(),
            kind,
        }
    }

    /// Patch the relocation into `template`, instantiated for the instruction `insn` at `pc`, at
    /// `template_start` in the output.
    #[inline(always)]
    fn apply<const SIZE: usize>(
        &self,
        template: &mut [MaybeUninit<u8>; SIZE],
        template_start: usize,
        pc: usize,
        insn: u64,
        pc_section: &[u32],
    ) {
        let off = (insn >> 16) as i16 as isize;
        let target = match self.kind {
            TemplateRelocationKind::InsnOffset => pc * ebpf::INSN_SIZE,
            TemplateRelocationKind::TakenBranchMeterAdjustment => {
                (off * ebpf::INSN_SIZE as isize) as usize
            }
            TemplateRelocationKind::TakenBranch => {
                let target_pc = (pc as isize)
                    .checked_add(1 + off)
                    .and_then(|target_pc| usize::try_from(target_pc).ok());
                // The verifier rejects invalid jump offsets…
                let target = target_pc
                    .and_then(|target_pc| pc_section.get(target_pc))
                    .copied()
                    .unwrap_or(JitTemplates::<SIZE>::INVALID_JUMP_TARGET);
                ((target & !PADDING_DUE) as usize).wrapping_sub(template_start)
            }
        };
        let value = target.wrapping_add(self.addend as usize);
        debug_assert!(
            i32::try_from(value as isize).is_ok(),
            "impossible relocation"
        );
        // Never clamps (see `new`), but `min` elides a bounds check.
        debug_assert!(usize::from(self.field) <= SIZE - 4);
        let field = usize::from(self.field).min(SIZE - 4);
        template[field..field + 4].write_copy_of_slice(&(value as u32).to_le_bytes());
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
    fn index(self) -> usize {
        TemplateOpcode::COUNT + self as usize
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

/// The JIT output for a program.
pub struct JitProgram {
    /// Offset in `text_section` for each BPF instruction.
    pub pc_section: Vec<u32>,
    /// The machine code.
    pub text_section: Vec<u8>,
}

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
        let start_padding =
            rng.gen_range(0..MAX_START_PADDING_LENGTH) * (noop_threshold != 0) as usize;

        let mut pc_sec = Vec::with_capacity(program.len());
        let mut position = 0;
        position += self.aux_layout(AuxTemplate::InvalidJumpTarget).len();
        position += start_padding * self.aux_layout(AuxTemplate::Noop).len();
        // Introduce checkpoints at certain points in the code; the instruction meter is otherwise
        // only checked on control flow, so straight-line code could run arbitrarily far past the
        // budget.
        let mut until_checkpoint = instruction_meter_checkpoint_distance;
        let mut program_iter = program.iter();
        while let Some(insn) = program_iter.next() {
            let insn = u64::from_le_bytes(*insn);
            let layout = self.insn_layout(TemplateOpcode::of(insn));
            let noop = if rng.next_u32() < noop_threshold {
                position += self.aux_layout(AuxTemplate::Noop).len();
                NOOP_DUE
            } else {
                0
            };
            let checkpoint = if layout.checks_meter {
                until_checkpoint = instruction_meter_checkpoint_distance;
                0
            } else if until_checkpoint == 0 {
                until_checkpoint = instruction_meter_checkpoint_distance;
                position += self.aux_layout(AuxTemplate::MeterCheckpoint).len();
                CHECKPOINT_DUE
            } else {
                until_checkpoint -= 1;
                0
            };
            // Truncation is ruled out below, once the final `position` is known.
            pc_sec.push(position as u32 | noop | checkpoint);
            position += layout.len();
            for _ in 0..layout.extra_bpf_insns {
                program_iter.next();
                pc_sec.push(Self::INVALID_JUMP_TARGET);
            }
        }
        position += self.aux_layout(AuxTemplate::ExecutionOverrun).len();
        assert!(position < NOOP_DUE as usize, "JIT output too large");
        (pc_sec, position, start_padding)
    }

    /// Compile the text section of `executable` into machine code.
    ///
    /// Due to the time sensitive nature of this code we try to do minimal amount of work here.
    /// The result is a two pass algorithm where the first pass determines ahead of time where
    /// each instruction's machine code will be, allowing for e.g. forward jump relocations to be
    /// resolved immediately during the emission.
    pub fn compile<C: ContextObject>(&self, executable: &Executable<C>) -> JitProgram {
        let (mut pc_sec, output_len, start_padding) = self.analyze(executable);
        // Templates are always written out in large chunks to employ SIMD and avoid memcpy calls.
        let mut text = Vec::with_capacity(output_len + SIZE);
        self.emit_aux(&mut text, &pc_sec, 0, AuxTemplate::InvalidJumpTarget);
        for _ in 0..start_padding {
            self.emit_aux(&mut text, &pc_sec, 0, AuxTemplate::Noop);
        }

        let bpf = executable.get_text_bytes().1;
        let (program, _) = bpf.as_chunks::<{ ebpf::INSN_SIZE }>();
        let mut program_iter = program.iter().zip(&pc_sec).enumerate();
        while let Some((pc, (insn, &entry))) = program_iter.next() {
            let insn = u64::from_le_bytes(*insn);
            let opcode = TemplateOpcode::of(insn);
            for _ in 0..self.insn_layout(opcode).extra_bpf_insns {
                program_iter.next();
            }
            if entry & PADDING_DUE != 0 {
                if entry & NOOP_DUE != 0 {
                    self.emit_aux(&mut text, &pc_sec, pc, AuxTemplate::Noop);
                }
                if entry & CHECKPOINT_DUE != 0 {
                    self.emit_aux(&mut text, &pc_sec, pc, AuxTemplate::MeterCheckpoint);
                }
            }
            self.emit(&mut text, &pc_sec, pc, insn, opcode.index());
        }
        let pc = program.len();
        self.emit_aux(&mut text, &pc_sec, pc, AuxTemplate::ExecutionOverrun);
        debug_assert_eq!(text.len(), output_len);
        for entry in &mut pc_sec {
            *entry &= !PADDING_DUE;
        }
        JitProgram {
            pc_section: pc_sec,
            text_section: text,
        }
    }

    fn insn_layout(&self, opcode: TemplateOpcode) -> TemplateLayout {
        self.layouts[opcode.index()]
    }

    fn aux_layout(&self, template: AuxTemplate) -> TemplateLayout {
        self.layouts[template.index()]
    }

    /// Append the `template` instantiated for `pc` to `text`, see `emit`.
    #[inline(always)]
    fn emit_aux(&self, text: &mut Vec<u8>, pc_section: &[u32], pc: usize, template: AuxTemplate) {
        self.emit(text, pc_section, pc, 0, template.index());
    }

    /// Append the template at `index` instantiated for the instruction `insn` at `pc` to `text`,
    /// which must have at least `SIZE` bytes of spare capacity.
    #[inline(always)]
    fn emit(&self, text: &mut Vec<u8>, pc_section: &[u32], pc: usize, insn: u64, index: usize) {
        let layout = self.layouts[index];
        let len = layout.len();
        let start = text.len();
        let out = text
            .spare_capacity_mut()
            .first_chunk_mut::<SIZE>()
            .expect("JIT output size miscalculated!");
        // Most of the templates are short, so they only get the first (fixed size) copy. The two
        // copies are disjoint so that they do not get merged into a single variable size memcpy.
        const SHORT: usize = 16;
        const { assert!(SIZE >= SHORT) };
        let (out_short, out_rest) = out.split_at_mut(SHORT);
        let (short, rest) = self.code[index].split_at(SHORT);
        out_short.write_copy_of_slice(short);
        if len > SHORT {
            out_rest.write_copy_of_slice(rest);
        }
        let relocations = &self.relocations[index][..usize::from(layout.num_relocations)];
        for relocation in relocations {
            relocation.apply(out, start, pc, insn, pc_section);
        }
        // SAFETY: just initialized at least the template's length past the end.
        unsafe { text.set_len(start + len) };
    }
}

#[cfg(all(feature = "codegen_debug", target_os = "linux"))]
/// Add the code in `ptr..ptr + len` called `name` to the perf jitdump (`/tmp/jit-<pid>.dump`).
fn write_perf_jitdump(name: &str, ptr: *const u8, len: usize, elf_machine: u32) {
    use std::io::Write as _;
    use std::os::fd::AsRawFd as _;
    use std::sync::{Mutex, OnceLock};
    // The header is only written once, then each of the code regions is a record of the same file,
    // and its index is the number of records before.
    static JITDUMP: OnceLock<Mutex<(std::fs::File, u64)>> = OnceLock::new();
    unsafe {
        let pid = std::process::id();
        let tid = libc::syscall(libc::SYS_gettid) as u32;
        let now = || {
            let mut ts = libc::timespec {
                tv_sec: 0,
                tv_nsec: 0,
            };
            libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut ts);
            (ts.tv_sec as u64) * 1_000_000_000 + ts.tv_nsec as u64
        };

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
            let m = libc::mmap(
                std::ptr::null_mut(),
                4096,
                libc::PROT_READ | libc::PROT_EXEC,
                libc::MAP_PRIVATE,
                f.as_raw_fd(),
                0,
            );
            if m != libc::MAP_FAILED {
                libc::munmap(m, 4096);
            }
            Mutex::new((f, 0))
        });
        let (f, records) = &mut *dump.lock().unwrap();

        // 2. JIT_CODE_LOAD Record Header (56 bytes, then the name and its NUL)
        let rec_size = (56 + name.len() + 1 + len) as u32;
        f.write_all(&0u32.to_le_bytes()).unwrap(); // ID: JIT_CODE_LOAD
        f.write_all(&rec_size.to_le_bytes()).unwrap();
        f.write_all(&now().to_le_bytes()).unwrap();
        f.write_all(&pid.to_le_bytes()).unwrap();
        f.write_all(&tid.to_le_bytes()).unwrap();
        f.write_all(&(ptr as u64).to_le_bytes()).unwrap(); // VMA
        f.write_all(&(ptr as u64).to_le_bytes()).unwrap(); // Code Address
        f.write_all(&(len as u64).to_le_bytes()).unwrap(); // Code Size
        f.write_all(&(*records + 1).to_le_bytes()).unwrap(); // Index
        f.write_all(name.as_bytes()).unwrap();
        f.write_all(&[0]).unwrap();
        *records += 1;

        // 3. Raw Code Bytes
        f.write_all(std::slice::from_raw_parts(ptr, len)).unwrap();
    }
}

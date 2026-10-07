//! Unified JIT and interpreted execution of BPF code.
//!
//! TODO: write some design philosphies here.

// Everything here is used by the architecture specific backends, of which there may be none.
#![cfg_attr(not(target_arch = "x86_64"), allow(dead_code, unused_imports))]

#[cfg(all(feature = "codegen-debug", target_arch = "x86_64"))]
pub mod debug;
#[cfg(target_arch = "x86_64")]
mod x64;
#[cfg(target_arch = "x86_64")]
use x64 as arch;

#[cfg(target_arch = "x86_64")]
mod generate;
#[cfg(target_arch = "x86_64")]
use arch::{TemplateRelocation, TemplateRelocationKind, MAX_RELOCATIONS};
#[cfg(target_arch = "x86_64")]
pub use generate::jit_templates;
#[cfg(target_arch = "x86_64")]
use generate::{Reg, TemplateBuilder, TemplateOpcode};

use crate::ebpf;
use crate::elf::Executable;
use crate::error::{EbpfError, ProgramResult};
pub use crate::program::JitProgram;
use crate::program::SBPFVersion;
use crate::vm::{ContextObject, EbpfVm};
use rand::rngs::SmallRng;
use rand::{thread_rng, Rng, RngCore, SeedableRng};
use std::convert::TryInto;
use std::num::NonZeroU64;

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
    arch::enter(executable, None, vm)
}

impl JitProgram {
    #[cfg(target_arch = "x86_64")]
    pub(crate) fn dynasm_invoke<C: ContextObject>(
        &self,
        executable: &Executable<C>,
        vm: &mut EbpfVm<C>,
    ) {
        arch::enter(executable, Some(self), vm)
    }
}

/// Where a template is instantiated, for `arch::TemplateRelocation::apply`.
struct Instantiation<'a> {
    /// The offsets in the output of the instructions.
    pc_section: &'a [u32],
    /// The offset in the output of `AuxTemplate::SigInvalidInsn`.
    sig_invalid_insn: usize,
    /// Likewise for `AuxTemplate::SigMeterExceeded`.
    sig_meter_exceeded: usize,
    /// The offset in the output the template is at.
    position: usize,
    /// Of the instruction the template is instantiated for.
    pc: usize,
    /// The `off` field of the instruction.
    off: i16,
    /// See [`JitProgram::random_key`].
    random_key: u32,
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
    /// byte instructions.) Continues into `InvalidInsn`, which follows it.
    InvalidCallTarget,
    /// Where the templates of invalid instructions continue, as if they were at its `pc`.
    SigInvalidInsn,
    /// Where the templates continue when the instruction meter is exceeded.
    SigMeterExceeded,
    /// Inserted between the other templates to diversify the output.
    Noop,
    /// Inserted ahead of an instruction (and instantiated for it) to check the instruction meter.
    MeterCheckpoint,
}

impl AuxTemplate {
    const COUNT: usize = 6;
    const ALL: [Self; Self::COUNT] = [
        Self::ExecutionOverrun,
        Self::InvalidCallTarget,
        Self::SigInvalidInsn,
        Self::SigMeterExceeded,
        Self::Noop,
        Self::MeterCheckpoint,
    ];
    /// Emitted at the start of the output, in this order.
    const SHARED: [Self; 3] = [
        Self::InvalidCallTarget,
        Self::SigInvalidInsn,
        Self::SigMeterExceeded,
    ];
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
/// Bound of `JitProgram::insn_bias`, and of the length of the text section the JIT compiles, so
/// that the biased offsets in the text fit 32-bit displacements.
const MAX_INSN_BIAS: u32 = 1 << 28;

impl<const SIZE: usize> JitTemplates<SIZE> {
    /// Offset of the `AuxTemplate::InvalidCallTarget` in the output, which is emitted first.
    const INVALID_CALL_TARGET: u32 = 0;

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

    /// The offsets in the output of the `AuxTemplate::SHARED` templates, which start it.
    fn shared_offsets(&self) -> [usize; AuxTemplate::SHARED.len()] {
        let mut end = 0usize;
        AuxTemplate::SHARED.map(|template| {
            let start = end;
            end = end.wrapping_add(self.aux_layout(template).len());
            start
        })
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
        for template in AuxTemplate::SHARED {
            position = position.wrapping_add(self.aux_layout(template).len());
        }
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
                pc_sec.push(Self::INVALID_CALL_TARGET);
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
        let bpf = executable.get_text_bytes().1;
        assert!(
            bpf.len() <= MAX_INSN_BIAS as usize,
            "text section too large for the JIT"
        );
        let random_key = if executable.get_config().sanitize_user_provided_values {
            thread_rng().gen_range(0..MAX_INSN_BIAS)
        } else {
            0
        };
        // Templates are always written out in large chunks to employ SIMD and avoid memcpy calls,
        // so the last one may extend past the output.
        // `output_len` is below `NOOP_DUE`, see `analyze`, and the sizes are far from `usize::MAX`.
        let mut program = JitProgram::new(pc_sec.len(), output_len.wrapping_add(SIZE));
        program.dynasm = true;
        program.random_key = random_key;
        #[cfg(all(feature = "codegen-debug", target_arch = "x86_64", target_os = "linux"))]
        debug::map_jit_text(&mut program);

        let text = program.text_section_mut();
        let [invalid_call_target, sig_invalid_insn, sig_meter_exceeded] = self.shared_offsets();
        debug_assert_eq!(invalid_call_target, Self::INVALID_CALL_TARGET as usize);
        let mut at = Instantiation {
            pc_section: &pc_sec,
            sig_invalid_insn,
            sig_meter_exceeded,
            position: 0,
            pc: 0,
            off: 0,
            random_key,
        };
        for template in AuxTemplate::SHARED {
            self.emit_aux(text, &mut at, template);
        }
        for _ in 0..start_padding {
            self.emit_aux(text, &mut at, AuxTemplate::Noop);
        }

        let (program_insns, _) = bpf.as_chunks::<{ ebpf::INSN_SIZE }>();
        let mut program_iter = program_insns.iter().zip(&pc_sec).enumerate();
        while let Some((pc, (insn, &entry))) = program_iter.next() {
            let insn = u64::from_le_bytes(*insn);
            let opcode = TemplateOpcode::of(insn);
            for _ in 0..self.insn_layout(opcode).extra_bpf_insns {
                program_iter.next();
            }
            at.pc = pc;
            at.off = (insn >> 16) as i16;
            if entry & PADDING_DUE != 0 {
                if entry & NOOP_DUE != 0 {
                    self.emit_aux(text, &mut at, AuxTemplate::Noop);
                }
                if entry & CHECKPOINT_DUE != 0 {
                    self.emit_aux(text, &mut at, AuxTemplate::MeterCheckpoint);
                }
            }
            self.emit(text, &mut at, opcode.index());
        }
        at.pc = program_insns.len();
        self.emit_aux(text, &mut at, AuxTemplate::ExecutionOverrun);
        debug_assert_eq!(at.position, output_len);
        for entry in &mut pc_sec {
            *entry &= !PADDING_DUE;
        }
        // The emission looks the jump targets up in the `Vec`, which is also the only place
        // the flags are in; it is small next to the machine code, so the copy is cheap.
        program.pc_section_mut().copy_from_slice(&pc_sec);
        program.seal(output_len)?;
        #[cfg(all(feature = "codegen-debug", target_arch = "x86_64", target_os = "linux"))]
        debug::finish_jit(self, executable, &mut program);
        Ok(program)
    }

    fn insn_layout(&self, opcode: TemplateOpcode) -> TemplateLayout {
        self.layouts[opcode.index()]
    }

    fn aux_layout(&self, template: AuxTemplate) -> TemplateLayout {
        self.layouts[template.index()]
    }

    /// Write the `template` to `text`, see `emit`.
    #[inline(always)]
    fn emit_aux(&self, text: &mut [u8], at: &mut Instantiation, template: AuxTemplate) {
        self.emit(text, at, template.index());
    }

    /// Write the template at `index` to `text`, instantiated as `at` describes, and advance
    /// `at.position` past it.
    ///
    /// `text` must have at least `SIZE` bytes from `at.position` on.
    #[inline(always)]
    fn emit(&self, text: &mut [u8], at: &mut Instantiation, index: usize) {
        let layout = self.layouts[index];
        let len = layout.len();
        let start = at.position;
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
            relocation.apply(&self.code[index], out, at);
        }
        at.position = start.wrapping_add(len);
    }
}

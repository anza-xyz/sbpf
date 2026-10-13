//! Assembling the JIT output out of the machine code templates.

use super::arch::{self, TemplateRelocation, MAX_RELOCATIONS};
use super::generate::TemplateOpcode;
use crate::ebpf;
use crate::elf::Executable;
use crate::error::EbpfError;
use crate::memory_management::Mapping;
use crate::program::{JitProgram, UnsealedJitProgram};
use crate::vm::ContextObject;
use rand::rngs::SmallRng;
use rand::{thread_rng, Rng, RngCore, SeedableRng};
use std::convert::TryInto;

/// Where a template is instantiated, for [`arch::TemplateRelocation::apply`].
pub(super) struct Instantiation<'a> {
    /// The mapping of offsets from BPF instructions to their machine code.
    pub(super) pc_section: &'a [u32],
    /// The offset to [`AuxTemplate::SigInvalidInsn`].
    pub(super) sig_invalid_insn: usize,
    /// Likewise for [`AuxTemplate::SigMeterExceeded`].
    pub(super) sig_meter_exceeded: usize,
    /// The offset in the output this template is at.
    pub(super) position: usize,
    /// BPF instruction index.
    pub(super) pc: usize,
    /// The `off` field of the instruction.
    pub(super) off: i16,
    /// See [`JitProgram::random_key`].
    pub(super) random_key: u32,
}

/// What the first pass of [`JitTemplates::compile`] needs to know about a template.
#[derive(Clone, Copy, Debug)]
pub(super) struct TemplateLayout {
    pub(super) bytes: u8,
    pub(super) num_relocations: u8,
    /// Size of the BPF instruction this template is for, minus one.
    ///
    /// `LD_DW_IMM` template holds a 1, all others 0.
    pub(super) extra_bpf_insns: u8,
    /// Does the code check the instruction meter itself?
    pub(super) checks_meter: bool,
}

impl TemplateLayout {
    /// Length of the machine code.
    pub(super) fn len(self) -> usize {
        usize::from(self.bytes)
    }
}

/// The auxiliary JIT templates.
#[derive(Clone, Copy)]
#[repr(u8)]
pub(super) enum AuxTemplate {
    /// To be appended after the last instruction, to detect execution runaway.
    ExecutionOverrun,
    /// For `pc_section` entries that are not valid jump targets (e.g. the second halves of 16
    /// byte instructions.)
    InvalidCallTarget,
    /// Where the templates of invalid instructions jump to.
    SigInvalidInsn,
    /// Where the templates continue when the instruction meter is exceeded.
    SigMeterExceeded,
    /// Randomly inserted between other templates to diversify the output.
    Noop,
    /// Inserted ahead of an instruction to check the instruction meter.
    MeterCheckpoint,
}

impl AuxTemplate {
    const COUNT: usize = 6;
    pub(super) const ALL: [Self; Self::COUNT] = [
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

pub(super) const NUM_TEMPLATES: usize = TemplateOpcode::COUNT + AuxTemplate::COUNT;

/// Machine code templates the JIT output is assembled from.
pub struct JitTemplates<const SIZE: usize> {
    pub(super) layouts: Box<[TemplateLayout; NUM_TEMPLATES]>,
    pub(super) code: Box<[[u8; SIZE]; NUM_TEMPLATES]>,
    pub(super) relocations: Box<[[TemplateRelocation; MAX_RELOCATIONS]; NUM_TEMPLATES]>,
}

/// A bitflag set in `pc_section` by `JitTemplates::analyze` for the instructions that must be
/// preceded by a meter checkpoint.
const CHECKPOINT_DUE: u32 = 1 << 31;

/// Likewise for a no-op ahead of the instruction.
const NOOP_DUE: u32 = 1 << 30;

pub(super) const PADDING_DUE: u32 = CHECKPOINT_DUE | NOOP_DUE;

/// Longest run of no-ops `JitTemplates::compile` may insert at the beginning.
const MAX_START_PADDING_LENGTH: usize = 256;

/// Bound of [`JitProgram::random_key`].
///
/// `MAX_RANDOM_KEY + max_size_of_generated_program` should fit within 2^31 (for x64.)
const MAX_RANDOM_KEY: u32 = 1 << 28;

impl<const SIZE: usize> JitTemplates<SIZE> {
    /// Offset of the [`AuxTemplate::InvalidCallTarget`] in the output.
    pub(super) const INVALID_CALL_TARGET: u32 = 0;

    pub(super) fn empty() -> Self {
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

    /// The offsets of the [`AuxTemplate::SHARED`] templates.
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

    pub(super) fn insn_builder(&mut self, opcode: TemplateOpcode) -> TemplateBuilder<'_, SIZE> {
        self.builder(opcode.index())
    }

    pub(super) fn aux_builder(&mut self, template: AuxTemplate) -> TemplateBuilder<'_, SIZE> {
        self.builder(template.index())
    }

    /// First pass analysis of the program to be compiled.
    ///
    /// Returns the `pc_section` (with `PADDING_DUE` flags in it), the length of the machine code
    /// and the number of no-ops at the beginning.
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
        let mut rng = SmallRng::from_rng(thread_rng()).expect("failed to seed the rng");
        let noop_threshold = u32::MAX.checked_div(noop_instruction_rate).unwrap_or(0);
        let start_padding = rng
            .gen_range(0..MAX_START_PADDING_LENGTH)
            .wrapping_mul((noop_threshold != 0) as usize);

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
            } else if let Some(remaining) = until_checkpoint.checked_sub(1) {
                until_checkpoint = remaining;
                0
            } else {
                until_checkpoint = instruction_meter_checkpoint_distance;
                position =
                    position.wrapping_add(self.aux_layout(AuxTemplate::MeterCheckpoint).len());
                CHECKPOINT_DUE
            };
            // Once the final `position` is known we double check that these bits are okay to use.
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
    /// The first pass determines where the machine code of each instruction will be, so that the
    /// second pass can resolve all relocations, including forward jumps, as it copies the
    /// templates.
    pub fn compile<C: ContextObject>(
        &self,
        executable: &Executable<C>,
    ) -> Result<JitProgram, EbpfError> {
        let (mut pc_sec, output_len, start_padding) = self.analyze(executable);
        let bpf = executable.get_text_bytes().1;
        assert!(
            bpf.len() <= MAX_RANDOM_KEY as usize,
            "text section too large for the JIT"
        );
        let random_key = thread_rng().gen_range(0..MAX_RANDOM_KEY);
        // Templates are always written out in large chunks to employ SIMD and avoid memcpy calls.
        // This necessitates some additional padding so we don't stomp other allocations.
        let code_capacity = output_len.wrapping_add(SIZE);
        let len = UnsealedJitProgram::mapping_len(pc_sec.len(), code_capacity);
        let mapping = Mapping::pooled(len);
        // The pc section is written in whole below, so the recycled memory need not be zeroed.
        let mut program = UnsealedJitProgram::in_mapping(mapping, pc_sec.len(), code_capacity);

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
        program.pc_section_mut().copy_from_slice(&pc_sec);
        let mut program = program.seal(output_len)?;
        program.parrot = true;
        program.random_key = random_key;
        Ok(program)
    }

    pub(super) fn insn_layout(&self, opcode: TemplateOpcode) -> TemplateLayout {
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

    /// Write the template at `index` to `text`, instantiated as `at` describes.
    ///
    /// `text` must have at least `SIZE` bytes available.
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

pub(super) struct TemplateBuilder<'a, const SIZE: usize> {
    pub(super) layout: &'a mut TemplateLayout,
    pub(super) code: &'a mut [u8; SIZE],
    pub(super) relocations: &'a mut [TemplateRelocation; arch::MAX_RELOCATIONS],
}

impl<const SIZE: usize> TemplateBuilder<'_, SIZE> {
    pub(super) fn code_mut(&mut self) -> &mut [u8] {
        &mut self.code[..self.layout.len()]
    }

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

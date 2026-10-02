// Everything here is used by the architecture specific backends, of which there may be none.
#![cfg_attr(not(target_arch = "x86_64"), allow(dead_code, unused_imports))]

#[cfg(target_arch = "x86_64")]
pub mod x64;

use crate::ebpf;
use crate::elf::Executable;
use crate::error::{EbpfError, ProgramResult};
use crate::vm::{ContextObject, EbpfVm};
use dynasmrt::components::{LabelRegistry, PatchLoc, RelocRegistry};
use dynasmrt::relocations::{Relocation, RelocationKind};
use dynasmrt::{AssemblyOffset, DynamicLabel};
use rand::rngs::SmallRng;
use rand::{thread_rng, Rng, RngCore, SeedableRng};
use std::convert::TryFrom;
use std::mem::MaybeUninit;

/// Size of the stack frame allocated for each internal call (fixed frames, as in SBPFv3.)
const STACK_FRAME_SIZE: i32 = 4096;
/// Maximum internal call depth (as in SBPFv3.)
const MAX_CALL_DEPTH: i32 = 64;

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
    (bpf.as_ptr() as u64).wrapping_add(pc.wrapping_add(budget).wrapping_mul(ebpf::INSN_SIZE as u64))
}

/// Update `vm` after the generated code has terminated with `code`, leaving `meter` behind.
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

/// The instruction a template is generated for: the opcode and the destination and source
/// registers.
#[derive(Clone, Copy)]
struct TemplateInsn {
    op: u8,
    dst: u8,
    src: u8,
}

/// Every instruction to generate a template for, with BPF register numbers, in the order of the
/// lower 16 bits of the instruction (the opcode, then the `dst` and `src` register numbers), which
/// is how the templates are looked up.
fn template_insns() -> impl Iterator<Item = TemplateInsn> {
    (0..=u16::MAX).map(|bits| TemplateInsn {
        op: bits as u8,
        dst: (bits >> 8 & 0xf) as u8,
        src: (bits >> 12) as u8,
    })
}

#[cfg(target_arch = "x86_64")]
/// Compile `executable` and execute it, starting at `vm.registers[11]`.
pub fn jit_and_run<C: ContextObject>(executable: &Executable<C>, vm: &mut EbpfVm<C>) {
    let (bpf_vm_addr, bpf) = executable.get_text_bytes();
    let noop_instruction_rate = executable.get_config().noop_instruction_rate;
    let program = x64::JIT_TEMPLATES.compile(bpf, noop_instruction_rate);
    let code = &program.text_section;
    let mut buffer = dynasmrt::mmap::MutableBuffer::new(code.len())
        .expect("failed to allocate executable memory for the JIT output");
    buffer.set_len(code.len());
    buffer.copy_from_slice(code);
    let buffer = buffer
        .make_exec()
        .expect("failed to make the JIT output executable");
    let start_addr =
        buffer.as_ptr() as usize + program.pc_section[vm.registers[11] as usize] as usize;
    vm.set_text_section(bpf, bpf_vm_addr);
    vm.jit_pc_section = program.pc_section.as_ptr();
    vm.jit_text_section = buffer.as_ptr();
    // The JIT output addresses the instructions relative to the second one.
    x64::enter(
        bpf,
        start_addr,
        bpf.as_ptr().wrapping_add(ebpf::INSN_SIZE),
        vm,
    )
}

#[cfg(target_arch = "x86_64")]
/// Interpret `executable`, starting at `vm.registers[11]`.
pub fn interpret_and_run<C: ContextObject>(executable: &Executable<C>, vm: &mut EbpfVm<C>) {
    let (bpf_vm_addr, bpf) = executable.get_text_bytes();
    let pc = vm.registers[11] as usize;
    let insn = &bpf[pc * ebpf::INSN_SIZE..][..2];
    let step = x64::interpreter_step(u16::from_le_bytes(<[u8; 2]>::try_from(insn).unwrap()));
    vm.set_text_section(bpf, bpf_vm_addr);
    vm.jit_pc_section = std::ptr::null();
    vm.jit_text_section = std::ptr::null();
    // The interpreter steps expect `insn` to point past the instruction being executed.
    let insn = bpf.as_ptr().wrapping_add((pc + 1) * ebpf::INSN_SIZE);
    x64::enter(bpf, step as usize, insn, vm)
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum MemoryAccessKind {
    Load,
    StoreImm,
    StoreReg,
}

const MAX_RELOCATIONS: usize = 8;

#[derive(Copy, Clone)]
struct Template<const SIZE: usize, R: Copy> {
    buffer: [u8; SIZE],
    bytes: usize,
    // Relocations based on BPF instruction contents (offset, immediate) for which this template is
    // instantiated for.
    relocations: [std::mem::MaybeUninit<R>; MAX_RELOCATIONS],
    num_relocations: usize,
}

impl<const SIZE: usize, R: Copy> Template<SIZE, R> {
    pub const fn new() -> Self {
        Self {
            buffer: [0; SIZE],
            bytes: 0,
            relocations: [std::mem::MaybeUninit::uninit(); MAX_RELOCATIONS],
            num_relocations: 0,
        }
    }

    pub const fn buffer_mut(&mut self) -> &mut [u8] {
        unsafe { std::slice::from_raw_parts_mut(self.buffer.as_mut_ptr(), self.bytes) }
    }

    pub const fn relocations(&self) -> &[R] {
        unsafe {
            std::slice::from_raw_parts(self.relocations.as_ptr().cast::<R>(), self.num_relocations)
        }
    }

    pub const fn add_relocation(&mut self, relocation: R) {
        self.relocations[self.num_relocations].write(relocation);
        self.num_relocations += 1;
    }

    #[track_caller]
    pub const fn extend(&mut self, buffer: &[u8]) {
        let mut i = 0;
        while i < buffer.len() {
            self.buffer[self.bytes] = buffer[i];
            self.bytes += 1;
            i += 1;
        }
    }

    pub const fn offset(&self) -> usize {
        self.bytes
    }

    pub const fn push(&mut self, byte: u8) {
        self.buffer[self.bytes] = byte;
        self.bytes += 1;
    }

    pub const fn push_i8(&mut self, value: i8) {
        self.push(value as u8);
    }

    pub const fn push_i32(&mut self, value: i32) {
        self.extend(&i32::to_le_bytes(value));
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

#[derive(Clone, Copy)]
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
#[derive(Clone, Copy)]
struct TemplateRelocation {
    /// Offset of the field within the template.
    field: u8,
    /// For relative relocations, this already accounts for where the field is in the template,
    /// but not for where the template is in the output.
    addend: i32,
    kind: TemplateRelocationKind,
}

impl TemplateRelocation {
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
                // FIXME: the verifier should have rejected these.
                let target = *target_pc
                    .and_then(|target_pc| pc_section.get(target_pc))
                    .expect("branch target out of bounds");
                (target as usize).wrapping_sub(template_start)
            }
        };
        let value = target.wrapping_add(self.addend as usize);
        debug_assert!(
            i32::try_from(value as isize).is_ok(),
            "impossible relocation"
        );
        // Never clamps (see `new`), but lets the bounds checks go.
        debug_assert!(usize::from(self.field) <= SIZE - 4);
        let field = usize::from(self.field).min(SIZE - 4);
        template[field..field + 4].write_copy_of_slice(&(value as u32).to_le_bytes());
    }
}

/// Machine code templates the JIT output is assembled from.
pub struct JitTemplates<const SIZE: usize> {
    /// Indexed by the lower 16 bits of an instruction.
    insns: Vec<Template<SIZE, TemplateRelocation>>,
    /// Appended after the last instruction, as if it was at `pc = program.len()`.
    execution_overrun: Template<SIZE, TemplateRelocation>,
    /// For `pc_section` entries that are not valid jump targets (e.g. the second
    /// halves of 16 byte instructions.)
    invalid_jump_target: Template<SIZE, TemplateRelocation>,
    /// Inserted between the other templates to diversify the output.
    noop: Template<SIZE, TemplateRelocation>,
}

/// Longest run of no-ops `JitTemplates::compile` may insert ahead of the code.
const MAX_START_PADDING_LENGTH: usize = 256;

/// The JIT output for a program.
pub struct JitProgram {
    /// Offset in `text_section` for each BPF instruction.
    pub pc_section: Vec<u32>,
    /// The machine code.
    pub text_section: Vec<u8>,
}

impl<const SIZE: usize> JitTemplates<SIZE> {
    /// Compile `bpf` into machine code.
    ///
    /// Due to the time sensitive nature of this code we try to do minimal amount of work here.
    /// The result is a two pass algorithm where the first pass determines ahead of time where
    /// each instruction's machine code will be, allowing for e.g. forward jump relocations to be
    /// resolved immediately during the emission.
    ///
    /// See `Config::noop_instruction_rate` for `noop_instruction_rate`.
    pub fn compile(&self, bpf: &[u8], noop_instruction_rate: u32) -> JitProgram {
        let (program, rest) = bpf.as_chunks::<{ ebpf::INSN_SIZE }>();
        assert!(rest.is_empty());
        let invalid_jump_target_loc = 0;

        // The no-ops diversify the output like `JitCompiler` does, except that they can only go in
        // between the templates, so the rate counts templates rather than host instructions. A
        // no-op goes before a template with the probability of 1 / `noop_instruction_rate` (never
        // for 0), decided by one `next_u32` each, so that the second pass can replay the decisions
        // of the first one with a clone of the RNG.
        let mut rng =
            SmallRng::from_rng(thread_rng()).expect("failed to seed the JIT diversification");
        let start_padding = if noop_instruction_rate == 0 {
            0
        } else {
            rng.gen_range(0..MAX_START_PADDING_LENGTH)
        };
        let noop_threshold = u32::MAX.checked_div(noop_instruction_rate).unwrap_or(0);

        let mut pc_sec = Vec::with_capacity(program.len());
        let mut position = self.invalid_jump_target.offset();
        let mut first_pass_rng = rng.clone();
        position += start_padding * self.noop.offset();
        let mut program_iter = program.iter();
        while let Some(insn) = program_iter.next() {
            let insn_size = insn_size(insn[0]);
            let insn = u64::from_le_bytes(*insn);
            let template = &self.insns[insn as u16 as usize];
            if first_pass_rng.next_u32() < noop_threshold {
                position += self.noop.offset();
            }
            pc_sec.push(u32::try_from(position).expect("JIT output too large"));
            position += template.offset();
            for _ in 1..(insn_size / 8) {
                program_iter.next();
                pc_sec.push(invalid_jump_target_loc);
            }
        }
        position += self.execution_overrun.offset();

        // Templates are always written out in large chunks to employ SIMD and avoid memcpy calls.
        let mut text = Vec::with_capacity(position + SIZE);
        Self::emit(&mut text, &pc_sec, 0, 0, &self.invalid_jump_target);
        for _ in 0..start_padding {
            Self::emit(&mut text, &pc_sec, 0, 0, &self.noop);
        }
        let mut program_iter = program.iter().enumerate();
        while let Some((pc, insn)) = program_iter.next() {
            let insn = u64::from_le_bytes(*insn);
            for _ in 1..(insn_size(insn as u8) / 8) {
                program_iter.next();
            }
            if rng.next_u32() < noop_threshold {
                Self::emit(&mut text, &pc_sec, 0, 0, &self.noop);
            }
            let tpl = &self.insns[insn as u16 as usize];
            Self::emit(&mut text, &pc_sec, pc, insn, tpl);
        }
        Self::emit(
            &mut text,
            &pc_sec,
            program.len(),
            0,
            &self.execution_overrun,
        );
        debug_assert_eq!(text.len(), position);
        JitProgram {
            pc_section: pc_sec,
            text_section: text,
        }
    }

    /// Append `template` instantiated for the instruction `insn` at `pc` to `text`, which must
    /// have at least `SIZE` bytes of spare capacity.
    #[inline(always)]
    fn emit(
        text: &mut Vec<u8>,
        pc_section: &[u32],
        pc: usize,
        insn: u64,
        template: &Template<SIZE, TemplateRelocation>,
    ) {
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
        let (short, rest) = template.buffer.split_at(SHORT);
        out_short.write_copy_of_slice(short);
        if template.offset() > SHORT {
            out_rest.write_copy_of_slice(rest);
        }
        for relocation in template.relocations() {
            relocation.apply(out, start, pc, insn, pc_section);
        }
        // SAFETY: just initialized at least the template's length past the end.
        unsafe { text.set_len(start + template.offset()) };
    }
}

#[cfg(all(feature = "codegen_debug", target_os = "linux"))]
/// Emit a perf jitdump (`/tmp/jit-<pid>.dump`) describing the code in `ptr..ptr + len`.
fn write_perf_jitdump(ptr: *const u8, len: usize, elf_machine: u32) {
    use std::io::Write as _;
    use std::os::fd::AsRawFd as _;
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

        // 2. JIT_CODE_LOAD Record Header (60 bytes = 56 byte record + 4 byte name)
        let rec_size = (60 + len) as u32;
        f.write_all(&0u32.to_le_bytes()).unwrap(); // ID: JIT_CODE_LOAD
        f.write_all(&rec_size.to_le_bytes()).unwrap();
        f.write_all(&now().to_le_bytes()).unwrap();
        f.write_all(&pid.to_le_bytes()).unwrap();
        f.write_all(&tid.to_le_bytes()).unwrap();
        f.write_all(&(ptr as u64).to_le_bytes()).unwrap(); // VMA
        f.write_all(&(ptr as u64).to_le_bytes()).unwrap(); // Code Address
        f.write_all(&(len as u64).to_le_bytes()).unwrap(); // Code Size
        f.write_all(&1u64.to_le_bytes()).unwrap(); // Index
        f.write_all(b"jit\0").unwrap(); // Symbol Name

        // 3. Raw Code Bytes
        f.write_all(std::slice::from_raw_parts(ptr, len)).unwrap();
    }
}

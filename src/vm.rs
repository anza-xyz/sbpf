#![allow(clippy::arithmetic_side_effects)]
// Derived from uBPF <https://github.com/iovisor/ubpf>
// Copyright 2015 Big Switch Networks, Inc
//      (uBPF: VM architecture, parts of the interpreter, originally in C)
// Copyright 2016 6WIND S.A. <quentin.monnet@6wind.com>
//      (Translation to Rust, MetaBuff/multiple classes addition, hashmaps for syscalls)
// Copyright 2020 Solana Maintainers <maintainers@solana.com>
//
// Licensed under the Apache License, Version 2.0 <http://www.apache.org/licenses/LICENSE-2.0> or
// the MIT license <http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

//! Virtual machine for eBPF programs.

use crate::{
    ebpf,
    elf::Executable,
    error::{EbpfError, ProgramResult},
    interpreter::Interpreter,
    memory_region::MemoryMapping,
    program::{BuiltinFunction, BuiltinProgram, FunctionRegistry, SBPFVersion},
    static_analysis::{Analysis, DummyContextObject, RegisterTraceEntry},
};
// Re-export defaults for direct access without the module path.
pub use defaults::get_stack_frame_size;
use std::{collections::BTreeMap, fmt::Debug, marker::PhantomData, mem::offset_of, ptr};

#[cfg(feature = "shuttle-test")]
use shuttle::sync::Arc;
#[cfg(not(feature = "shuttle-test"))]
use std::sync::Arc;

#[cfg(all(feature = "jit", not(feature = "shuttle-test")))]
use rand::{thread_rng, Rng};
#[cfg(all(feature = "jit", feature = "shuttle-test"))]
use shuttle::rand::{thread_rng, Rng};

/// Returns (and if not done before generates) the encryption key for the VM pointer
#[cfg(feature = "jit")]
pub fn get_runtime_environment_key() -> i32 {
    static RUNTIME_ENVIRONMENT_KEY: std::sync::OnceLock<i32> = std::sync::OnceLock::new();
    *RUNTIME_ENVIRONMENT_KEY.get_or_init(|| thread_rng().gen::<i32>() >> 1)
}

#[cfg(not(feature = "jit"))]
pub fn get_runtime_environment_key() -> i32 {
    0
}

/// Default VM configuration settings.
pub(crate) mod defaults {
    const DEFAULT_STACK_FRAME_SIZE: usize = 4_096;

    /// Returns the stack frame size in bytes.
    ///
    /// With the `conf-stack-frame-size` feature enabled, the size can be overridden
    /// at runtime via the `VM_STACK_FRAME_SIZE` environment variable. The value is
    /// read once and cached. If not set, the default is always returned.
    ///
    /// Note: the `conf-stack-frame-size` variant can't be `const fn` (it uses
    /// `OnceLock`), while the production variant is `const fn`. Callers that need
    /// `const` evaluation (e.g. array sizes, const generics) should be aware that
    /// those uses will not compile when `conf-stack-frame-size` is enabled.
    #[cfg(feature = "conf-stack-frame-size")]
    #[inline(always)]
    pub fn get_stack_frame_size() -> usize {
        static STACK_FRAME_SIZE_CACHE: std::sync::OnceLock<usize> = std::sync::OnceLock::new();
        *STACK_FRAME_SIZE_CACHE.get_or_init(|| {
            let size = std::env::var("VM_STACK_FRAME_SIZE")
                .ok()
                .and_then(|v| {
                    v.parse::<usize>().ok().filter(|sfz| *sfz > 0).or_else(|| {
                        log::warn!(
                            "Invalid VM_STACK_FRAME_SIZE={}, falling back to {}.",
                            v,
                            DEFAULT_STACK_FRAME_SIZE
                        );
                        None
                    })
                })
                .unwrap_or(DEFAULT_STACK_FRAME_SIZE);
            if size != DEFAULT_STACK_FRAME_SIZE {
                log::warn!(
                    "VM_STACK_FRAME_SIZE is set to {} (default: {}).",
                    size,
                    DEFAULT_STACK_FRAME_SIZE
                );
            }
            size
        })
    }

    /// Returns the stack frame size in bytes.
    #[cfg(not(feature = "conf-stack-frame-size"))]
    pub const fn get_stack_frame_size() -> usize {
        DEFAULT_STACK_FRAME_SIZE
    }
}

/// Specify the execution method.
pub enum ExecutionMode {
    /// Execute the program in an interpreted mode.
    Interpreted,
    /// Execute the program in JIT mode.
    ///
    /// The program must be JIT compiled.
    Jit,
    /// Allow JIT execution, if compiled. Otherwise fallback to interpreted.
    PreferJit,
}

/// VM configuration settings
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Config {
    /// Maximum call depth
    pub max_call_depth: usize,
    /// Size of a stack frame in bytes, must match the size specified in the LLVM BPF backend
    pub stack_frame_size: usize,
    /// Enables the use of MemoryMapping and MemoryRegion for address translation
    pub enable_address_translation: bool,
    /// Enables gaps in VM address space between the stack frames
    pub enable_stack_frame_gaps: bool,
    /// Maximal pc distance after which a new instruction meter validation is emitted by the JIT
    pub instruction_meter_checkpoint_distance: usize,
    /// Enable instruction meter and limiting
    pub enable_instruction_meter: bool,
    /// Enable instruction tracing
    pub enable_register_tracing: bool,
    /// Enable dynamic string allocation for labels
    pub enable_symbol_and_section_labels: bool,
    /// Reject ELF files containing issues that the verifier did not catch before (up to v0.2.21)
    pub reject_broken_elfs: bool,
    #[cfg(feature = "jit")]
    /// Ratio of native host instructions per random no-op in JIT (0 = OFF)
    pub noop_instruction_rate: u32,
    #[cfg(feature = "jit")]
    /// Enable disinfection of immediate values and offsets provided by the user in JIT
    pub sanitize_user_provided_values: bool,
    /// Avoid copying read only sections when possible
    pub optimize_rodata: bool,
    /// Use aligned memory mapping
    pub aligned_memory_mapping: bool,
    /// Allowed [SBPFVersion]s
    pub enabled_sbpf_versions: std::ops::RangeInclusive<SBPFVersion>,
}

impl Config {
    /// Returns the size of the stack memory region
    pub fn stack_size(&self) -> usize {
        self.stack_frame_size * self.max_call_depth
    }
}

impl Default for Config {
    fn default() -> Self {
        Self {
            max_call_depth: 64,
            stack_frame_size: defaults::get_stack_frame_size(),
            enable_address_translation: true,
            enable_stack_frame_gaps: true,
            instruction_meter_checkpoint_distance: 10000,
            enable_instruction_meter: true,
            enable_register_tracing: false,
            enable_symbol_and_section_labels: false,
            reject_broken_elfs: false,
            #[cfg(feature = "jit")]
            noop_instruction_rate: 256,
            #[cfg(feature = "jit")]
            sanitize_user_provided_values: true,
            optimize_rodata: true,
            aligned_memory_mapping: false,
            enabled_sbpf_versions: SBPFVersion::V0..=SBPFVersion::V4,
        }
    }
}

/// Static constructors for Executable
impl<C: ContextObject> Executable<C> {
    /// Creates an executable from an ELF file
    pub fn from_elf(elf_bytes: &[u8], loader: Arc<BuiltinProgram<C>>) -> Result<Self, EbpfError> {
        let executable = Executable::load(elf_bytes, loader)?;
        Ok(executable)
    }
    /// Creates an executable from machine code
    pub fn from_text_bytes(
        text_bytes: &[u8],
        loader: Arc<BuiltinProgram<C>>,
        sbpf_version: SBPFVersion,
        function_registry: FunctionRegistry<usize>,
    ) -> Result<Self, EbpfError> {
        Executable::new_from_text_bytes(text_bytes, loader, sbpf_version, function_registry)
            .map_err(EbpfError::ElfError)
    }
}

/// Runtime context
pub trait ContextObject {
    /// Consume instructions from meter
    fn consume(&mut self, amount: u64);
    /// Get the number of remaining instructions allowed
    fn get_remaining(&self) -> u64;
    /// Return a mutable pointer to the active MemoryMapping
    fn active_mapping_ptr(&mut self) -> ptr::NonNull<MemoryMapping>;
}

/// Statistic of taken branches (from a recorded trace)
pub struct DynamicAnalysis {
    /// Maximal edge counter value
    pub edge_counter_max: usize,
    /// src_node, dst_node, edge_counter
    pub edges: BTreeMap<usize, BTreeMap<usize, usize>>,
}

impl DynamicAnalysis {
    /// Accumulates a trace
    pub fn new(register_trace: &[[u64; 12]], analysis: &Analysis) -> Self {
        let mut result = Self {
            edge_counter_max: 0,
            edges: BTreeMap::new(),
        };
        let mut last_basic_block = usize::MAX;
        for traced_instruction in register_trace.iter() {
            let pc = traced_instruction[11] as usize;
            if analysis.cfg_nodes.contains_key(&pc) {
                let counter = result
                    .edges
                    .entry(last_basic_block)
                    .or_default()
                    .entry(pc)
                    .or_insert(0);
                *counter += 1;
                result.edge_counter_max = result.edge_counter_max.max(*counter);
                last_basic_block = pc;
            }
        }
        result
    }
}

/// One recorded syscall invocation
#[derive(Clone, Debug)]
pub struct SyscallTraceEntry {
    pub pc: u64,
    pub program_id: [u8; 32],
    pub name: String,
    pub args: [u64; 5],
    pub result: u64,
    pub function_pc: u64,
    pub call_depth: u64,
}

/// One recorded memory load or store
#[derive(Clone, Debug)]
pub struct MemTraceEntry {
    pub pc: u64,
    pub program_id: [u8; 32],
    pub is_store: bool,
    pub size: u8,
    pub vm_addr: u64,
    pub value: u64,
    pub account_idx: Option<usize>,
    pub account_offset: Option<u64>,
    pub function_pc: u64,
    pub call_depth: u64,
    /// All 12 registers at match time; only filled when `capture_regs_on_mem_match` is true
    pub regs: Option<[u64; 12]>,
}

/// One recorded instruction execution
#[derive(Clone, Debug)]
pub struct InsnTraceEntry {
    pub pc: u64,
    pub program_id: [u8; 32],
    pub opcode: u8,
    pub opcode_name: &'static str,
    pub category: &'static str,
    pub dst: u8,
    pub src: u8,
    pub imm: i64,
    pub off: i16,
    pub dst_val_before: u64,
    pub dst_val_after: u64,
    pub src_val: u64,
    /// For jump instructions: true if branch was taken
    pub branch_taken: Option<bool>,
    /// For jump instructions: target PC if taken
    pub branch_target: Option<u64>,
    pub function_pc: u64,
    pub call_depth: u64,
}

/// Memory dump result captured at a specific PC
#[derive(Clone, Debug, Default)]
pub struct MemDumpResult {
    pub pc: u64,
    pub program_id: [u8; 32],
    pub vm_addr: u64,
    pub bytes: Vec<u8>,
}

/// Register snapshot captured at a specific PC
#[derive(Clone, Debug, Default)]
pub struct RegSnapshot {
    pub pc: u64,
    pub program_id: [u8; 32],
    pub regs: [u64; 12],
}

/// CPI (cross-program invocation) decode entry
#[derive(Clone, Debug, Default)]
pub struct CpiDecodeEntry {
    pub pc: u64,
    pub program_id: [u8; 32],
    pub accounts_len: u64,
    pub data_len: u64,
    pub data_preview: Vec<u8>,
}

/// One recorded function call or return
#[derive(Clone, Debug)]
pub struct CallTraceEntry {
    /// PC of the CALL or RETURN instruction
    pub pc: u64,
    pub program_id: [u8; 32],
    /// Target PC (for CALL: callee entry; for RETURN: return-to PC)
    pub target_pc: u64,
    /// function_pc at the time this instruction executes
    pub function_pc: u64,
    /// call_depth BEFORE this instruction (so for CALL: depth before push; for RETURN: depth after pop)
    pub call_depth: u64,
    /// true = RETURN, false = CALL
    pub is_return: bool,
    /// r0-r5 at the moment of CALL (args) or r0 at RETURN (return value)
    pub args: [u64; 6],
}

/// VM address range of one serialized account's data region
#[derive(Clone, Debug)]
pub struct AccountVmRange {
    pub vm_start: u64,
    pub vm_end: u64,
    pub account_idx: usize,
}

/// Instruction category flags for --trace-insn filtering
#[derive(Clone, Debug, Default)]
pub struct InsnTraceCategories {
    pub call: bool,
    pub jump: bool,
    pub alu: bool,
}

/// Trace filtering configuration set by the host
#[derive(Clone, Debug, Default)]
pub struct TraceConfig {
    pub trace_syscalls: bool,
    pub trace_mem: bool,
    pub trace_stream: bool,
    pub trace_mem_read: bool,
    pub trace_mem_write: bool,
    pub trace_mem_sizes: Vec<u8>,
    pub trace_mem_offset_start: Option<u64>,
    pub trace_mem_offset_end: Option<u64>,
    pub trace_insn: bool,
    pub insn_categories: InsnTraceCategories,
    pub target_program_addr: Option<u64>,
    /// When set, only record trace entries from this program_id
    pub trace_filter_program_id: Option<[u8; 32]>,
    pub trace_mem_account_idx: Option<usize>,
    pub account_ranges: Vec<AccountVmRange>,
    pub dump_mem_specs: Vec<(u64, u64, u64)>,
    pub trace_regs_at_pcs: Vec<u64>,
    pub trace_mem_value_match: Option<u64>,
    pub trace_pc_range: Option<(u64, u64)>,
    pub trace_function_pc: Option<u64>,
    pub trace_cpi_decode: bool,
    pub current_program_id: [u8; 32],
    /// Record every CALL and RETURN with args/return-value
    pub trace_calls: bool,
    /// When a mem_trace entry matches trace_mem_value_match, also record all 12 registers
    pub capture_regs_on_mem_match: bool,
    /// Print when ALU dst register matches this value
    pub trace_alu_value_match: Option<u64>,
}

#[derive(Clone, Debug)]
pub enum TraceEvent {
    Syscall(SyscallTraceEntry),
    MemAccess(MemTraceEntry),
    Instruction(InsnTraceEntry),
    Call(CallTraceEntry),
    CpiDecode(CpiDecodeEntry),
    MemDump(MemDumpResult),
    RegSnapshot(RegSnapshot),
}

fn bytes_to_hex(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|byte| format!("{:02x}", byte))
        .collect::<String>()
}

impl TraceEvent {
    pub fn stream_print(&self) {
        match self {
            TraceEvent::Syscall(e) => eprintln!(
                "[SBPF_STREAM] SYSCALL pc={} name={} args=[{:#x},{:#x},{:#x},{:#x},{:#x}] result={:#x} program={}",
                e.pc,
                e.name,
                e.args[0],
                e.args[1],
                e.args[2],
                e.args[3],
                e.args[4],
                e.result,
                bytes_to_hex(&e.program_id)
            ),
            TraceEvent::MemAccess(e) => eprintln!(
                "[SBPF_STREAM] MEM {} {}B @ {:#x} val={:#x} acct={:?} off={:?} program={}",
                if e.is_store { "STORE" } else { "LOAD" },
                e.size,
                e.vm_addr,
                e.value,
                e.account_idx,
                e.account_offset,
                bytes_to_hex(&e.program_id)
            ),
            TraceEvent::Instruction(e) => eprintln!(
                "[SBPF_STREAM] INSN pc={} {} dst_before={:#x} dst_after={:#x} program={}",
                e.pc,
                e.opcode_name,
                e.dst_val_before,
                e.dst_val_after,
                bytes_to_hex(&e.program_id)
            ),
            TraceEvent::Call(e) => eprintln!(
                "[SBPF_STREAM] {} pc={} target={} depth={} program={}",
                if e.is_return { "RET" } else { "CALL" },
                e.pc,
                e.target_pc,
                e.call_depth,
                bytes_to_hex(&e.program_id)
            ),
            TraceEvent::CpiDecode(e) => eprintln!(
                "[SBPF_STREAM] CPI pc={} target_program={} accounts_len={} data_len={} program={}",
                e.pc,
                bytes_to_hex(&e.program_id),
                e.accounts_len,
                e.data_len,
                bytes_to_hex(&e.program_id)
            ),
            TraceEvent::MemDump(e) => eprintln!(
                "[SBPF_STREAM] MEMDUMP pc={} addr={:#x} len={} program={}",
                e.pc,
                e.vm_addr,
                e.bytes.len(),
                bytes_to_hex(&e.program_id)
            ),
            TraceEvent::RegSnapshot(e) => eprintln!(
                "[SBPF_STREAM] REGS pc={} r0={:#x} r1={:#x} r2={:#x} program={}",
                e.pc,
                e.regs[0],
                e.regs[1],
                e.regs[2],
                bytes_to_hex(&e.program_id)
            ),
        }
    }
}
/// A call frame used for function calls inside the Interpreter
#[derive(Clone, Default)]
pub struct CallFrame {
    /// The caller saved registers
    pub caller_saved_registers: [u64; ebpf::SCRATCH_REGS],
    /// The callers frame pointer
    pub frame_pointer: u64,
    /// The target_pc of the exit instruction which returns back to the caller
    pub target_pc: u64,
}

/// Indices of slots inside [EbpfVm]
pub enum RuntimeEnvironmentSlot {
    /// [EbpfVm::host_stack_pointer]
    HostStackPointer = offset_of!(EbpfVm<DummyContextObject>, host_stack_pointer) as isize,
    /// [EbpfVm::call_depth]
    CallDepth = offset_of!(EbpfVm<DummyContextObject>, call_depth) as isize,
    /// [EbpfVm::context_object_pointer]
    ContextObjectPointer = offset_of!(EbpfVm<DummyContextObject>, context_object_pointer) as isize,
    /// [EbpfVm::previous_instruction_meter]
    PreviousInstructionMeter =
        offset_of!(EbpfVm<DummyContextObject>, previous_instruction_meter) as isize,
    /// [EbpfVm::due_insn_count]
    DueInsnCount = offset_of!(EbpfVm<DummyContextObject>, due_insn_count) as isize,
    /// [EbpfVm::stopwatch_numerator]
    StopwatchNumerator = offset_of!(EbpfVm<DummyContextObject>, stopwatch_numerator) as isize,
    /// [EbpfVm::stopwatch_denominator]
    StopwatchDenominator = offset_of!(EbpfVm<DummyContextObject>, stopwatch_denominator) as isize,
    /// [EbpfVm::registers]
    Registers = offset_of!(EbpfVm<DummyContextObject>, registers) as isize,
    /// [EbpfVm::program_result]
    ProgramResult = offset_of!(EbpfVm<DummyContextObject>, program_result) as isize,
    /// [EbpfVm::memory_mapping]
    MemoryMapping = offset_of!(EbpfVm<DummyContextObject>, memory_mapping) as isize,
    /// [EbpfVm::register_trace]
    RegisterTrace = offset_of!(EbpfVm<DummyContextObject>, register_trace) as isize,
}

/// A virtual machine to run eBPF programs.
///
/// # Examples
///
/// ```
/// use solana_sbpf::{
///     aligned_memory::AlignedMemory,
///     ebpf,
///     elf::Executable,
///     memory_region::{MemoryMapping, MemoryRegion},
///     program::{BuiltinProgram, FunctionRegistry, SBPFVersion},
///     verifier::RequisiteVerifier,
///     vm::{CallFrame, Config, EbpfVm, ExecutionMode},
/// };
/// use test_utils::TestContextObject;
///
/// let prog = &[
///     0x07, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // add64 r0, 0
///     0x95, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00  // exit
/// ];
/// let mut mem: [u8; _] = [0xaa, 0xbb, 0x11, 0x22, 0xcc, 0xdd];
///
/// let loader = std::sync::Arc::new(BuiltinProgram::new_mock());
/// let function_registry = FunctionRegistry::default();
/// let mut executable = Executable::<TestContextObject>::from_text_bytes(prog, loader.clone(), SBPFVersion::V4, function_registry).unwrap();
/// executable.verify::<RequisiteVerifier>().unwrap();
/// let mut context_object = TestContextObject::new(2);
/// let sbpf_version = executable.get_sbpf_version();
///
/// let mut stack = AlignedMemory::<{ebpf::HOST_ALIGN}>::zero_filled(executable.get_config().stack_size());
/// let stack_len = stack.len();
/// let mut heap = AlignedMemory::<{ebpf::HOST_ALIGN}>::with_capacity(0);
///
/// let regions: Vec<MemoryRegion> = vec![
///     executable.get_ro_region(),
///     MemoryRegion::new(&mut stack, ebpf::MM_STACK_START),
///     MemoryRegion::new(&mut heap, ebpf::MM_HEAP_START),
///     MemoryRegion::new(&raw mut mem, ebpf::MM_INPUT_START),
/// ];
///;
/// context_object.memory_mapping = unsafe {
///     MemoryMapping::new(regions, executable.get_config(), sbpf_version).unwrap()
/// };
///
/// let mut vm = EbpfVm::new(loader, sbpf_version, &mut context_object, stack_len);
///
/// let mut call_frames = vec![CallFrame::default(); executable.get_config().max_call_depth];
/// let (instruction_count, result) = vm.execute_program(
///     &executable,
///     &mut ExecutionMode::Interpreted,
///     &mut call_frames,
/// );
/// assert_eq!(instruction_count, 2);
/// assert_eq!(result.unwrap(), 0);
/// ```
#[repr(C)]
pub struct EbpfVm<'a, C: ContextObject> {
    /// Needed to exit from the guest back into the host
    pub host_stack_pointer: *mut u64,
    /// The current call depth.
    ///
    /// Incremented on calls and decremented on exits. It's used to enforce
    /// config.max_call_depth and to know when to terminate execution.
    pub call_depth: u64,
    /// Pointer to ContextObject
    pub(crate) context_object_pointer: ptr::NonNull<C>,
    /// The lifetime for the context object pointer
    context_object_lifetime: PhantomData<&'a mut C>,
    /// Last return value of instruction_meter.get_remaining()
    pub previous_instruction_meter: u64,
    /// Outstanding value to instruction_meter.consume()
    pub due_insn_count: u64,
    /// CPU cycles accumulated by the stop watch
    pub stopwatch_numerator: u64,
    /// Number of times the stop watch was used
    pub stopwatch_denominator: u64,
    /// Registers inlined
    pub registers: [u64; 12],
    /// ProgramResult inlined
    pub program_result: ProgramResult,
    /// MemoryMapping inlined
    pub(crate) memory_mapping: ptr::NonNull<MemoryMapping>,
    /// Loader built-in program
    pub loader: Arc<BuiltinProgram<C>>,
    /// Collector for the instruction trace
    pub register_trace: Vec<RegisterTraceEntry>,
    pub syscall_trace: Vec<SyscallTraceEntry>,
    pub mem_trace: Vec<MemTraceEntry>,
    pub insn_trace: Vec<InsnTraceEntry>,
    pub call_trace: Vec<CallTraceEntry>,
    pub mem_dump_results: Vec<MemDumpResult>,
    pub reg_snapshots: Vec<RegSnapshot>,
    pub cpi_decode_trace: Vec<CpiDecodeEntry>,
    pub trace_config: TraceConfig,
    /// TCP port for the debugger interface
    #[cfg(feature = "debugger")]
    pub debug_port: Option<u16>,
    /// Debug metadata passed
    #[cfg(feature = "debugger")]
    pub debug_metadata: Option<String>,
}

impl<'a, C: ContextObject> EbpfVm<'a, C> {
    /// Creates a new virtual machine instance.
    pub fn new(
        loader: Arc<BuiltinProgram<C>>,
        sbpf_version: SBPFVersion,
        context_object: &'a mut C,
        stack_len: usize,
    ) -> Self {
        let config = loader.get_config();
        let mut registers = [0u64; 12];
        registers[ebpf::FRAME_PTR_REG] =
            ebpf::MM_STACK_START.saturating_add(if !sbpf_version.manual_stack_frame_bump() {
                config.stack_frame_size
            } else {
                stack_len
            } as u64);

        let memory_mapping = context_object.active_mapping_ptr();
        EbpfVm {
            host_stack_pointer: std::ptr::null_mut(),
            call_depth: 0,
            context_object_pointer: ptr::NonNull::from_mut(context_object),
            context_object_lifetime: PhantomData,
            previous_instruction_meter: 0,
            due_insn_count: 0,
            stopwatch_numerator: 0,
            stopwatch_denominator: 0,
            registers,
            program_result: ProgramResult::Ok(0),
            memory_mapping,
            loader,
            #[cfg(feature = "debugger")]
            debug_port: std::env::var("VM_DEBUG_PORT")
                .ok()
                .and_then(|v| v.parse::<u16>().ok()),
            #[cfg(feature = "debugger")]
            debug_metadata: None,
            register_trace: Vec::default(),
            syscall_trace: Vec::new(),
            mem_trace: Vec::new(),
            insn_trace: Vec::new(),
            call_trace: Vec::new(),
            mem_dump_results: Vec::new(),
            reg_snapshots: Vec::new(),
            cpi_decode_trace: Vec::new(),
            trace_config: TraceConfig::default(),
        }
    }

    /// Execute the program
    ///
    /// Use `mode` parameter to request a specific execution type. This function will write back
    /// the execution mode used back to the reference passed in.
    ///
    /// It is required to provide `call_frames` when executing in interpreted mode.
    /// `call_frames` must be large enough to hold the executable config's `max_call_depth`
    /// frames.
    ///
    /// Returns the instruction meter count (CUs) and the execution result of the program.
    pub fn execute_program(
        &mut self,
        executable: &Executable<C>,
        mode: &mut ExecutionMode,
        call_frames: &mut [CallFrame],
    ) -> (u64, ProgramResult) {
        let trace_enabled = std::env::var("SBPF_TRACE").is_ok();
        if trace_enabled {
            *mode = ExecutionMode::Interpreted; // fix: dereference
        }

        debug_assert!(Arc::ptr_eq(&self.loader, executable.get_loader()));
        self.registers[11] = executable.get_entrypoint_instruction_offset() as u64;
        let config = executable.get_config();
        let initial_insn_count = self.context().get_remaining();
        self.previous_instruction_meter = initial_insn_count;
        self.due_insn_count = 0;
        self.program_result = ProgramResult::Ok(0);

        if std::env::var("SBPF_DEBUG_SYSVAR").is_ok() {
            self.debug_dump_serialized_input();
        }

        'execute: {
            match *mode {
                ExecutionMode::Interpreted => {
                    #[cfg(feature = "debugger")]
                    let debug_port = self.debug_port.clone();

                    let mut interpreter =
                        Interpreter::new(self, executable, self.registers, call_frames);

                    if trace_enabled {
                        // fix: only print when tracing
                        let (prog_addr, prog_bytes) = executable.get_text_bytes();
                        eprintln!(
                            "[SBPF_TRACE] === START prog=0x{:x} len={} ===",
                            prog_addr,
                            prog_bytes.len()
                        );
                    }

                    #[cfg(feature = "debugger")]
                    if let Some(debug_port) = debug_port {
                        crate::debugger::execute(&mut interpreter, debug_port);
                    } else {
                        while interpreter.step() {}
                    }
                    #[cfg(not(feature = "debugger"))]
                    while interpreter.step() {}

                    interpreter.dump_trace_on_error();

                    break 'execute; // fix: explicit break so we don't hit bottom
                }

                #[cfg(all(feature = "jit", not(target_os = "windows"), target_arch = "x86_64"))]
                ExecutionMode::PreferJit => {
                    if let Some(compiled_program) = executable.get_compiled_program() {
                        *mode = ExecutionMode::Jit;
                        break 'execute compiled_program.invoke(config, self, self.registers);
                    }
                    // fallthrough to interpreted below
                }
                #[cfg(not(all(
                    feature = "jit",
                    not(target_os = "windows"),
                    target_arch = "x86_64"
                )))]
                ExecutionMode::PreferJit => {}

                #[cfg(all(feature = "jit", not(target_os = "windows"), target_arch = "x86_64"))]
                ExecutionMode::Jit => {
                    let Some(compiled_program) = executable.get_compiled_program() else {
                        return (0, ProgramResult::Err(EbpfError::JitNotCompiled));
                    };
                    break 'execute compiled_program.invoke(config, self, self.registers);
                }
                #[cfg(not(all(
                    feature = "jit",
                    not(target_os = "windows"),
                    target_arch = "x86_64"
                )))]
                ExecutionMode::Jit => return (0, ProgramResult::Err(EbpfError::JitNotCompiled)),
            }

            *mode = ExecutionMode::Interpreted;
            let mut interpreter = Interpreter::new(self, executable, self.registers, call_frames);
            while interpreter.step() {}
        }

        let instruction_count = if config.enable_instruction_meter {
            let due_insn_count = self.due_insn_count;
            let context = self.context();
            context.consume(due_insn_count);
            initial_insn_count.saturating_sub(context.get_remaining())
        } else {
            0
        };
        let mut result = ProgramResult::Ok(0);
        std::mem::swap(&mut result, &mut self.program_result);
        (instruction_count, result)
    }
    fn debug_dump_serialized_input(&self) {
        use std::convert::TryInto;
        // Sysvar1nstructions1111111111111111111111111
        const SYSVAR_IX_KEY: [u8; 32] = [
            0x06, 0xa7, 0xd5, 0x17, 0x18, 0x7b, 0xd1, 0x6b, 0xcb, 0x35, 0xa1, 0x22, 0xa1, 0x7b,
            0x7c, 0xe2, 0x55, 0xdf, 0xbf, 0x41, 0x03, 0xef, 0x19, 0xd1, 0x40, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
        ];

        let mm = unsafe { &self.memory_mapping.read() };
        let all_regions = mm.get_regions();
        let input_start = crate::ebpf::MM_INPUT_START;

        // Filter to INPUT space regions only (vm_addr >= MM_INPUT_START)
        eprintln!(
            "[SBPF_DEBUG] === all regions: {} total, scanning INPUT space (>= 0x{:x}) ===",
            all_regions.len(),
            input_start
        );

        let mut sysvar_found = false;
        let mut sysvar_data_region: Option<(u64, u64, u64)> = None; // (host, vm, len)

        for (idx, r) in all_regions.iter().enumerate() {
            if r.vm_addr_range().start < input_start {
                continue;
            }
            let len = r.len() as usize;
            if len == 0 {
                continue;
            }

            let data = unsafe { &*r.host_buffer().ptr() };

            // Search for SYSVAR_IX_KEY in this region
            if len >= 32 {
                for pos in 0..len.saturating_sub(31) {
                    if &data[pos..pos + 32] == &SYSVAR_IX_KEY {
                        sysvar_found = true;
                        eprintln!(
                            "[SBPF_DEBUG]   region[{}] vm=0x{:x} len={}: SYSVAR_IX_KEY at offset {} (vm 0x{:x})",
                            idx, r.vm_addr_range().start , len, pos, r.vm_addr_range().start  + pos as u64
                        );
                        // Key is at offset 8 within account header
                        if pos >= 8 {
                            let hdr_start = pos - 8;
                            let marker = data[hdr_start];
                            eprintln!(
                                "[SBPF_DEBUG]     header marker=0x{:02x} (0xff=original)",
                                marker
                            );
                            if hdr_start + 88 <= len {
                                let dl = u64::from_le_bytes(
                                    data[hdr_start + 80..hdr_start + 88].try_into().unwrap(),
                                );
                                eprintln!("[SBPF_DEBUG]     data_len={}", dl);
                                // The next region should contain sysvar data
                                // data is mapped at vm_addr + 88 from the header start
                                // but with direct mapping, data is in a SEPARATE region
                                sysvar_data_region = Some((
                                    0,
                                    r.vm_addr_range().start + (hdr_start as u64) + 88,
                                    dl,
                                ));
                            }
                        }
                        // Dump context around key
                        let ctx_end = (pos + 96).min(len);
                        eprintln!(
                            "[SBPF_DEBUG]     context [{}..{}]: {:02x?}",
                            pos,
                            ctx_end,
                            &data[pos..ctx_end]
                        );
                    }
                }
            }

            // Check for sysvar data signature (03 00 = 3 instructions)
            if len >= 4 && data[0] == 0x03 && data[1] == 0x00 {
                eprintln!(
                    "[SBPF_DEBUG]   region[{}] vm=0x{:x} len={}: POSSIBLE SYSVAR DATA (starts 03 00)",
                    idx, r.vm_addr_range().start , len
                );
                if len >= 4 {
                    let cur_ix = u16::from_le_bytes(data[len - 2..].try_into().unwrap());
                    eprintln!("[SBPF_DEBUG]     current_ix={}, total_len={}", cur_ix, len);
                }
                let num_ix = u16::from_le_bytes(data[0..2].try_into().unwrap()) as usize;
                for ix_i in 0..num_ix.min(4) {
                    let off =
                        u16::from_le_bytes(data[2 + 2 * ix_i..4 + 2 * ix_i].try_into().unwrap())
                            as usize;
                    if off + 2 <= len {
                        let na =
                            u16::from_le_bytes(data[off..off + 2].try_into().unwrap()) as usize;
                        let pid_off = off + 2 + 33 * na;
                        if pid_off + 32 <= len {
                            eprintln!(
                                "[SBPF_DEBUG]     ix[{}] off={} num_accounts={} program_id={:02x?}",
                                ix_i,
                                off,
                                na,
                                &data[pid_off..pid_off + 32]
                            );
                        } else {
                            eprintln!(
                                "[SBPF_DEBUG]     ix[{}] off={} num_accounts={} pid_off={} OUT_OF_BOUNDS",
                                ix_i, off, na, pid_off
                            );
                        }
                    }
                }
            }
        }

        // If sysvar key found but need to find its data region
        if let Some((_, expected_vm, expected_len)) = sysvar_data_region {
            eprintln!(
                "[SBPF_DEBUG]   looking for sysvar data region at vm=0x{:x} len={}",
                expected_vm, expected_len
            );
            if let Some((found_idx, found_r)) = mm.find_region(expected_vm) {
                let data_offset = (expected_vm - found_r.vm_addr_range().start) as usize;
                let avail = (found_r.len() as usize).saturating_sub(data_offset);
                let read_len = avail.min(expected_len as usize);
                let sdata = unsafe { &*found_r.host_buffer().ptr() };
                eprintln!(
                    "[SBPF_DEBUG]   sysvar data found in region[{}] vm=0x{:x}, read {} bytes",
                    found_idx,
                    found_r.vm_addr_range().start,
                    read_len
                );
                if read_len >= 2 {
                    let num_ix = u16::from_le_bytes(sdata[0..2].try_into().unwrap());
                    eprintln!("[SBPF_DEBUG]     num_instructions={}", num_ix);
                }
                let dump_len = read_len.min(200);
                eprintln!(
                    "[SBPF_DEBUG]     first {} bytes: {:02x?}",
                    dump_len,
                    &sdata[..dump_len]
                );
                if read_len >= 4 {
                    let cur_ix =
                        u16::from_le_bytes(sdata[read_len - 2..read_len].try_into().unwrap());
                    eprintln!("[SBPF_DEBUG]     current_instruction_index={}", cur_ix);
                }
            } else {
                eprintln!(
                    "[SBPF_DEBUG]   *** SYSVAR DATA REGION NOT FOUND at vm=0x{:x} ***",
                    expected_vm
                );
            }
        }

        if !sysvar_found {
            eprintln!(
                "[SBPF_DEBUG]   *** NO SYSVAR_INSTRUCTIONS KEY FOUND IN ANY INPUT REGION ***"
            );
            // Dump summary of all INPUT regions for diagnosis
            for (idx, r) in all_regions.iter().enumerate() {
                if r.vm_addr_range().start < input_start || r.len() == 0 {
                    continue;
                }
                let len = r.len() as usize;
                let data = unsafe { &*r.host_buffer().ptr() };
                eprintln!(
                    "[SBPF_DEBUG]     region[{}] vm=0x{:x} len={} first_bytes={:02x?}",
                    idx,
                    r.vm_addr_range().start,
                    len,
                    data
                );
            }
        }
        eprintln!("[SBPF_DEBUG] === end scan ===");
    }
    /// Invokes a built-in function
    pub fn invoke_function(&mut self, function: BuiltinFunction<C>) {
        function(
            self.encrypted_host_address(),
            self.registers[1],
            self.registers[2],
            self.registers[3],
            self.registers[4],
            self.registers[5],
        );
    }

    /// Build a `VmAddress` containing a (potentially) encrypted host pointer to self.
    ///
    /// Note that this type is effectively a mutable pointer to `self` and although it valid to
    /// create multiple of these addresses, using them to violate the Rust mutable references'
    /// uniqueness rule is not sound.
    pub(crate) fn encrypted_host_address(&mut self) -> EncryptedHostAddressToEbpfVm<C> {
        let addr = (&raw mut *self).expose_provenance() as isize;
        EncryptedHostAddressToEbpfVm(
            addr.wrapping_add(get_runtime_environment_key() as isize) as usize as u64,
            PhantomData,
        )
    }

    /// Get a reference to the context object referenced by this EbpfVm.
    pub fn context(&mut self) -> &mut C {
        // SAFETY: we've the unique reference to self here, so there can't be other live references
        // to `C` either, whether via the memory_mapping or the context_object_pointer itself.
        //
        // The `context_object_pointer` is pointing at a valid-to-dereference `C` at all times
        // through the EbpfVm lifetime.
        //
        // Note: for that reason we are intentionally tying the lifetime of the returned `C` to the
        // lifetime of `&mut self`, rather than returning `&'a mut C`, which would allow aliasing
        // the returned reference.
        unsafe { self.context_object_pointer.as_mut() }
    }

    // Intentionally not public. Users are expected to store their memory mapping inside – and
    // access from – C.
    pub(crate) fn memory(&mut self) -> &mut MemoryMapping {
        // SAFETY: we've the unique reference to self here, so there can't be other live references
        // to `C` either, whether via the memory_mapping or the context_object_pointer itself.
        //
        // The `context_object_pointer` is pointing at a valid-to-dereference `C` at all times
        // through the EbpfVm lifetime.
        unsafe { self.memory_mapping.as_mut() }
    }
}

/// Encrypted address to the [`EbpfVm`] object.
#[repr(transparent)]
pub struct EncryptedHostAddressToEbpfVm<C>(
    // This ends up having to be public to the crate because inline assembly wants to deal with
    // integers, not `VmAddress` (even though VmAddress has the same layout.)
    pub(crate) u64,
    PhantomData<C>,
);

impl<C: ContextObject> EncryptedHostAddressToEbpfVm<C> {
    /// Work on [`EbpfVm`] pointed to by this address.
    ///
    /// ## Safety
    ///
    /// Multiple concurrently live addresses can reference the same [`EbpfVm`] but under no
    /// circumstances may they be used to create multiple concurrent mutable references to the
    /// `EbpfVm`.
    pub unsafe fn with_vm<R>(&mut self, cb: impl FnOnce(&mut EbpfVm<'_, C>) -> R) -> R {
        let addr = (self.0 as usize as isize)
            .wrapping_sub(crate::vm::get_runtime_environment_key() as isize);
        // SAFETY: we've recovered the same pointer address as that of the reference used to
        // produce this offset address in the first place.
        // SAFETY: The mutable reference is unique due to invariant being passed onto the caller.
        let vm = unsafe {
            std::ptr::with_exposed_provenance_mut::<crate::vm::EbpfVm<C>>(addr as usize)
                .as_mut()
                .unwrap()
        };
        cb(vm)
    }
}

#[cold]
#[inline(never)]
fn run_interpreter<C: ContextObject>(mut interpreter: Interpreter<C>) {
    #[cfg(feature = "debugger")]
    if let Some(debug_port) = interpreter.vm.debug_port.clone() {
        return crate::debugger::execute(&mut interpreter, debug_port);
    }

    while interpreter.step() {}
    interpreter.vm.registers[11] = interpreter.reg[11];
}

#[cfg(test)]
mod tests {
    use crate::{
        memory_region::MemoryMapping,
        program::{BuiltinProgram, SBPFVersion},
        vm::{Config, ContextObject, RuntimeEnvironmentSlot},
    };
    use std::{ptr::NonNull, sync::Arc};

    #[test]
    fn test_runtime_environment_slots() {
        struct DummyContextObject(MemoryMapping);
        impl ContextObject for DummyContextObject {
            fn consume(&mut self, _: u64) {
                todo!()
            }
            fn get_remaining(&self) -> u64 {
                todo!()
            }
            fn active_mapping_ptr(&mut self) -> NonNull<MemoryMapping> {
                NonNull::from_mut(&mut self.0)
            }
        }
        let version = SBPFVersion::V4;
        let config = Config::default();
        let mut context_object =
            unsafe { DummyContextObject(MemoryMapping::new(vec![], &config, version).unwrap()) };
        let env = super::EbpfVm::new(
            Arc::new(BuiltinProgram::new_mock()),
            version,
            &mut context_object,
            4096,
        );

        macro_rules! check_slot {
            ($env:expr, $entry:ident, $slot:ident) => {
                assert_eq!(
                    unsafe {
                        std::ptr::addr_of!($env.$entry)
                            .cast::<u8>()
                            .offset_from(std::ptr::addr_of!($env).cast::<u8>()) as usize
                    },
                    RuntimeEnvironmentSlot::$slot as usize,
                );
            };
        }

        check_slot!(env, host_stack_pointer, HostStackPointer);
        check_slot!(env, call_depth, CallDepth);
        check_slot!(env, context_object_pointer, ContextObjectPointer);
        check_slot!(env, previous_instruction_meter, PreviousInstructionMeter);
        check_slot!(env, due_insn_count, DueInsnCount);
        check_slot!(env, stopwatch_numerator, StopwatchNumerator);
        check_slot!(env, stopwatch_denominator, StopwatchDenominator);
        check_slot!(env, registers, Registers);
        check_slot!(env, program_result, ProgramResult);
        check_slot!(env, memory_mapping, MemoryMapping);
        check_slot!(env, register_trace, RegisterTrace);
    }
}


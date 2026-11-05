//! The host functions that the generated code calls.

use super::arch::host_abi;
use super::generate::Reg;
use crate::aligned_memory::Pod;
use crate::ebpf;
use crate::error::{EbpfError, ProgramResult};
use crate::program::{BuiltinFunction, FunctionRegistry, SBPFVersion};
use crate::vm::{ContextObject, EbpfVm};

/// Returned by the host functions, in two registers.
#[repr(C)]
pub(super) struct HostCallResult {
    pub(super) value: u64,
    pub(super) status: HostCallStatus,
}

#[repr(u8)]
pub(super) enum HostCallStatus {
    Ok = 0,
    /// The error has been stored into `vm.program_result`.
    Failed = 1,
    /// The SBPFv0 to v2 `CALL_IMM` is an internal call to the pc in `value`, see `dispatch_call`.
    CallInternal = 2,
}

impl HostCallResult {
    /// Failure with the error (if any) already in place.
    fn failed() -> Self {
        Self {
            value: 0,
            status: HostCallStatus::Failed,
        }
    }

    /// The outcome that `vm.program_result` has been set to.
    fn of_program_result<C: ContextObject>(vm: &mut EbpfVm<C>) -> Self {
        match vm.program_result {
            ProgramResult::Ok(value) => Self {
                value,
                status: HostCallStatus::Ok,
            },
            ProgramResult::Err(_) => Self::failed(),
        }
    }

    fn new(result: ProgramResult, program_result: &mut ProgramResult) -> Self {
        match result {
            ProgramResult::Ok(value) => Self {
                value,
                status: HostCallStatus::Ok,
            },
            err => {
                *program_result = err;
                Self::failed()
            }
        }
    }
}

/// The address of the function to call for `CALL_IMM`, given the version.
///
/// For SBPFv0 to v2 the function is [`dispatch_call`], which also resolves internal calls, otherwise
/// [`dispatch_syscall`].
pub(super) fn call_dispatcher<C: ContextObject>(version: SBPFVersion) -> *const u8 {
    if version.static_syscalls() {
        dispatch_syscall::<C> as *const u8
    } else {
        dispatch_call::<C> as *const u8
    }
}

host_abi! {
    /// The SBPFv0 to v2 `CALL_IMM`.
    fn dispatch_call<C: ContextObject>(
        vm: &mut EbpfVm<C>,
        key: u32,
        remaining: u64,
        internal_functions: &FunctionRegistry<usize>,
    ) -> HostCallResult {
        match vm.loader.get_function_registry().lookup_by_key(key) {
            Some((_, (function, _))) => invoke_syscall(vm, function, remaining),
            None => match internal_functions.lookup_by_key(key) {
                Some((_, target_pc)) => HostCallResult {
                    value: target_pc as u64,
                    status: HostCallStatus::CallInternal,
                },
                None => unsupported_syscall(vm, remaining),
            },
        }
    }
}

host_abi! {
    fn dispatch_syscall<C: ContextObject>(
        vm: &mut EbpfVm<C>,
        key: u32,
        remaining: u64,
    ) -> HostCallResult {
        // TODO: avoid the hashmap lookup on every syscall. Programs only ever run against a
        // handful of syscall sets, which could get dedicated interpreter/JIT variants with the
        // functions resolved ahead of time.
        match vm.loader.get_function_registry().lookup_by_key(key) {
            Some((_, (function, _))) => invoke_syscall(vm, function, remaining),
            None => unsupported_syscall(vm, remaining),
        }
    }
}

fn unsupported_syscall<C: ContextObject>(vm: &mut EbpfVm<C>, remaining: u64) -> HostCallResult {
    vm.program_result = ProgramResult::Err(EbpfError::UnsupportedInstruction);
    HostCallResult {
        value: remaining,
        status: HostCallStatus::Failed,
    }
}

fn invoke_syscall<C: ContextObject>(
    vm: &mut EbpfVm<C>,
    function: BuiltinFunction<C>,
    remaining: u64,
) -> HostCallResult {
    // `invoke_function` consumes `due_insn_count` from the budget and updates
    // `previous_instruction_meter` with what is left of it.
    vm.due_insn_count = vm.previous_instruction_meter.saturating_sub(remaining);
    vm.invoke_function(function);
    let status = match vm.program_result {
        ProgramResult::Ok(result) => {
            vm.registers[0] = result;
            HostCallStatus::Ok
        }
        ProgramResult::Err(_) => HostCallStatus::Failed,
    };
    HostCallResult {
        value: vm.previous_instruction_meter,
        status,
    }
}

#[cfg(feature = "tracer")]
host_abi! {
    pub(super) fn push_register_trace(
        vm: &mut EbpfVm<crate::static_analysis::DummyContextObject>,
    ) {
        vm.register_trace.push(vm.registers);
    }
}

/// For addressing `EbpfVm` fields regardless of the context object.
pub(super) type Vm = EbpfVm<'static, crate::static_analysis::DummyContextObject>;

/// Offset of the slot for `reg` in [`EbpfVm::registers`].
pub(super) const fn register_slot(reg: Reg) -> usize {
    std::mem::offset_of!(Vm, registers).wrapping_add((reg.0 as usize).wrapping_mul(8))
}

/// Offset of the slot for the pc in [`EbpfVm::registers`].
#[cfg(feature = "tracer")]
pub(super) const PC_SLOT: usize = register_slot(Reg(Reg::COUNT as u8));

/// The size of a memory access.
#[derive(Clone, Copy)]
pub(super) enum AccessSize {
    B,
    H,
    W,
    DW,
}

impl AccessSize {
    pub(super) const ALL: [Self; 4] = [Self::B, Self::H, Self::W, Self::DW];

    /// The size of the access done by the load or store with the opcode `op`.
    pub(super) fn of(op: u8) -> Self {
        match op & ebpf::BPF_SIZE_MASK {
            ebpf::BPF_B => Self::B,
            ebpf::BPF_H => Self::H,
            ebpf::BPF_W => Self::W,
            ebpf::BPF_DW => Self::DW,
            _ => unreachable!(),
        }
    }

    /// The size of the access done by the SBPFv2 load or store with the opcode `op`.
    pub(super) fn of_v2_opcode(op: u8) -> Self {
        match op & (ebpf::BPF_1B | ebpf::BPF_2B | ebpf::BPF_4B | ebpf::BPF_8B) {
            ebpf::BPF_1B => Self::B,
            ebpf::BPF_2B => Self::H,
            ebpf::BPF_4B => Self::W,
            ebpf::BPF_8B => Self::DW,
            _ => unreachable!(),
        }
    }

    /// Offset of the function for this access size in [`MemoryFunctions`] for loads.
    pub(super) fn load_offset(self) -> usize {
        std::mem::offset_of!(MemoryFunctions<DummyContextObject>, load)
            .wrapping_add((self as usize).wrapping_mul(8))
    }

    /// Likewise for stores.
    pub(super) fn store_offset(self) -> usize {
        std::mem::offset_of!(MemoryFunctions<DummyContextObject>, store)
            .wrapping_add((self as usize).wrapping_mul(8))
    }
}

type DummyContextObject = crate::static_analysis::DummyContextObject;

/// The functions for loads and stores, which depend on the [`ContextObject`] through the access
/// violation handler.
#[repr(C)]
pub(super) struct MemoryFunctions<C: ContextObject> {
    load: [host_abi!(fn(&mut EbpfVm<C>, u64, &mut MeterSlots) -> HostCallResult); 4],
    store: [host_abi!(fn(&mut EbpfVm<C>, u64, u64, &mut MeterSlots) -> HostCallResult); 4],
}

impl<C: ContextObject> MemoryFunctions<C> {
    const FUNCTIONS: Self = Self {
        load: [
            load::<u8, C>,
            load::<u16, C>,
            load::<u32, C>,
            load::<u64, C>,
        ],
        store: [
            store::<u8, C>,
            store::<u16, C>,
            store::<u32, C>,
            store::<u64, C>,
        ],
    };

    /// The address of the table of functions.
    pub(super) fn get() -> *const u8 {
        const { (&Self::FUNCTIONS as *const Self).cast::<u8>() }
    }
}

/// The instruction meter registers, spilled to memory for the memory functions.
#[repr(C)]
pub(super) struct MeterSlots {
    meter: u64,
    next_insn: u64,
}

impl MeterSlots {
    /// Tell the VM how much of the budget has been used up so far, the way the interpreter would
    /// have at the start of the instruction before `next_insn`.
    ///
    /// Returns `false` if the budget was exceeded already, in which case the instruction must not
    /// execute and the VM is left as is.
    fn hand_over_to_vm<C: ContextObject>(&self, vm: &mut EbpfVm<C>) -> bool {
        if self.next_insn > self.meter {
            return false;
        }
        let remaining = self.meter.wrapping_sub(self.next_insn)
            / const { std::num::NonZeroU64::new(ebpf::INSN_SIZE as u64).unwrap() };
        vm.due_insn_count = vm.previous_instruction_meter.saturating_sub(remaining);
        true
    }

    /// Take the budget back after something has consumed from it (and updated
    /// [`EbpfVm::previous_instruction_meter`]).
    fn take_back_from_vm<C: ContextObject>(&mut self, vm: &mut EbpfVm<C>) {
        vm.due_insn_count = 0;
        self.meter = self.next_insn.wrapping_add(
            vm.previous_instruction_meter
                .wrapping_mul(ebpf::INSN_SIZE as u64),
        );
    }
}

host_abi! {
    fn load<T: Pod + Into<u64>, C: ContextObject>(
        vm: &mut EbpfVm<C>,
        vm_addr: u64,
        meter: &mut MeterSlots,
    ) -> HostCallResult {
        if let result @ ProgramResult::Ok(_) = vm.memory().load_first_attempt::<T>(vm_addr) {
            return HostCallResult::new(result, &mut vm.program_result);
        }
        // The access violation handler may consume from the budget, so the VM needs to know how
        // much of it has been used up so far.
        if !meter.hand_over_to_vm(vm) {
            // The budget has been exceeded. That takes precedence over the memory error.
            return HostCallResult::failed();
        }
        let encrypted_vm = vm.encrypted_host_address();
        vm.memory()
            .load_second_attempt::<T, C>(vm_addr, encrypted_vm);
        meter.take_back_from_vm(vm);
        HostCallResult::of_program_result(vm)
    }
}

host_abi! {
    fn store<T: Pod, C: ContextObject>(
        vm: &mut EbpfVm<C>,
        vm_addr: u64,
        value: u64,
        meter: &mut MeterSlots,
    ) -> HostCallResult {
        const { assert!(cfg!(target_endian = "little")) };
        // SAFETY:
        //
        // Contract from `mem::transmute_copy`: This function will unsafely assume the pointer
        // `src` is valid for `size_of::<Dst>` bytes by transmuting `&Src` to `&Dst` and then
        // reading the `&Dst` (except that this is done in a way that is correct even when `&Dst`
        // has stricter alignment requirements than `&Src`).
        //
        // Contract from `mem::transmute_copy`: This function triggers undefined behavior if `Dst`
        // is larger than `Src`.
        //
        // Evidence: `store` is only instantiated for `u8`, `u16`, `u32` and `u64` (see
        // `MemoryFunctions::FUNCTIONS`), which are not larger than `u64`, and for which any bytes
        // are a valid value. `&value` is valid for 8 bytes, of which the first `size_of::<T>()`
        // are read, which on little endian are the low ones, so the value is truncated as
        // intended.
        let value = unsafe { std::mem::transmute_copy::<u64, T>(&value) };
        if let result @ ProgramResult::Ok(_) = vm.memory().store_first_attempt::<T>(value, vm_addr)
        {
            return HostCallResult::new(result, &mut vm.program_result);
        }
        if !meter.hand_over_to_vm(vm) {
            return HostCallResult::failed();
        }
        let encrypted_vm = vm.encrypted_host_address();
        vm.memory()
            .store_second_attempt::<T, C>(value, vm_addr, encrypted_vm);
        meter.take_back_from_vm(vm);
        HostCallResult::of_program_result(vm)
    }
}

//! The helpers for loads and stores.

use super::*;
use crate::vm::ContextObject;

/// The size of a memory access.
#[derive(Clone, Copy)]
pub(in crate::codegen) enum AccessSize {
    B,
    H,
    W,
    DW,
}

impl AccessSize {
    const ALL: [Self; 4] = [Self::B, Self::H, Self::W, Self::DW];

    /// The size of the access done by the load or store with the opcode `op`.
    pub(in crate::codegen) fn of(op: u8) -> Self {
        match op & ebpf::BPF_SIZE_MASK {
            ebpf::BPF_B => Self::B,
            ebpf::BPF_H => Self::H,
            ebpf::BPF_W => Self::W,
            ebpf::BPF_DW => Self::DW,
            _ => unreachable!(),
        }
    }

    /// The size of the access done by the SBPFv2 load or store with the opcode `op`.
    pub(in crate::codegen) fn of_v2_opcode(op: u8) -> Self {
        match op & (ebpf::BPF_1B | ebpf::BPF_2B | ebpf::BPF_4B | ebpf::BPF_8B) {
            ebpf::BPF_1B => Self::B,
            ebpf::BPF_2B => Self::H,
            ebpf::BPF_4B => Self::W,
            ebpf::BPF_8B => Self::DW,
            _ => unreachable!(),
        }
    }

    /// Offset of the function for this access size in [`MemoryFunctions::load`].
    fn load_offset(self) -> i8 {
        let offset = std::mem::offset_of!(MemoryFunctions<DummyContextObject>, load)
            .wrapping_add((self as usize).wrapping_mul(8));
        i8::try_from(offset).unwrap()
    }

    /// Offset of the function for this access size in [`MemoryFunctions::store`].
    fn store_offset(self) -> i8 {
        let offset = std::mem::offset_of!(MemoryFunctions<DummyContextObject>, store)
            .wrapping_add((self as usize).wrapping_mul(8));
        i8::try_from(offset).unwrap()
    }
}

type DummyContextObject = crate::static_analysis::DummyContextObject;

/// The memory [`SupportEntry`]s call these, as the access violation handler depends on the
/// [`ContextObject`].
///
/// See [`Frame::memory_functions`].
#[repr(C)]
pub(in crate::codegen) struct MemoryFunctions<C: ContextObject> {
    load: [extern "sysv64" fn(&mut EbpfVm<C>, u64, &mut MeterSlots) -> HostCallResult; 4],
    store: [extern "sysv64" fn(&mut EbpfVm<C>, u64, u64, &mut MeterSlots) -> HostCallResult; 4],
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

    /// The value for [`Frame::memory_functions`].
    pub(in crate::codegen) fn get() -> *const u8 {
        const { (&Self::FUNCTIONS as *const Self).cast::<u8>() }
    }
}

/// The meter registers as pushed by [`push_for_sysv64_call`].
#[repr(C)]
struct MeterSlots {
    /// `RMETER`
    meter: u64,
    /// `RTEMP`
    next_insn: u64,
}

impl MeterSlots {
    /// Where [`push_for_sysv64_call`] leaves these relative to `rsp`.
    const OFFSET_FROM_RSP: i8 = (BPF_SYSV64_CLOBBERED.count_ones() * 8) as i8;

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

/// Generate the [`SupportEntry`]s of the loads and stores.
pub(super) fn generate(out: &mut Asm, entries: &mut SupportEntries) {
    let failed = out.new_dynamic_label();
    for size in AccessSize::ALL {
        entries[SupportEntry::load(size) as usize] = generate_load(out, size, failed);
        entries[SupportEntry::store_imm(size) as usize] = generate_store(out, size, false, failed);
        entries[SupportEntry::store_reg(size) as usize] = generate_store(out, size, true, failed);
    }
    x64asm!(out
        ; =>failed
        // Running out of budget takes precedence over the memory error.
        ;; validate_meter(out)
        ;; terminate(out, SIG_PROGRAM_RESULT)
    );
}

/// Load `size` bytes into `RTEMP` from the address operand plus the offset of the instruction
/// preceding the address in `RTEMP`. Jumps to `failed` if the access fails.
fn generate_load(out: &mut Asm, size: AccessSize, failed: DynamicLabel) -> usize {
    let start = entry(out);
    let offset = size.load_offset();
    save_rinsn(out);
    push_for_sysv64_call(out);
    x64asm!(out
        ; movsx rsi, WORD [RTEMP - 6]
        ; add rsi, [BYTE frame_operand(0) + rbp]
        ; mov rdi, [BYTE frame!(vm) + rbp]
        ; lea rdx, [ BYTE MeterSlots::OFFSET_FROM_RSP + rsp ]
        ; mov rax, [BYTE frame!(memory_functions) + rbp]
        ; mov rax, [ BYTE offset + rax ]
        ;; debug_assert_sysv64_call_stack_alignment(out)
        ; call rax
        ; cmp dl, HostCallStatus::Ok as i8
        ;; pop_after_sysv64_call(out)
        ; jne =>failed
        ; mov RTEMP, rax
        ;; restore_rinsn_and_return(out)
    );
    start
}

/// Store `size` bytes of the value operand if `from_register` (or of the immediate), to the address
/// operand plus offset. Jumps to `failed` if the access fails.
fn generate_store(
    out: &mut Asm,
    size: AccessSize,
    from_register: bool,
    failed: DynamicLabel,
) -> usize {
    let start = entry(out);
    let offset = size.store_offset();
    save_rinsn(out);
    push_for_sysv64_call(out);
    let address = if from_register {
        x64asm!(out; mov rdx, [BYTE frame_operand(0) + rbp]);
        frame_operand(1)
    } else {
        x64asm!(out; movsxd rdx, DWORD [RTEMP - 4]);
        frame_operand(0)
    };
    x64asm!(out
        ; movsx rsi, WORD [RTEMP - 6]
        ; add rsi, [BYTE address + rbp]
        ; mov rdi, [BYTE frame!(vm) + rbp]
        // SUBTLE: `rcx` is `RTEMP`, which is not needed anymore.
        ; lea rcx, [ BYTE MeterSlots::OFFSET_FROM_RSP + rsp ]
        ; mov rax, [BYTE frame!(memory_functions) + rbp]
        ; mov rax, [ BYTE offset + rax ]
        ;; debug_assert_sysv64_call_stack_alignment(out)
        ; call rax
        ; cmp dl, HostCallStatus::Ok as i8
        ;; pop_after_sysv64_call(out)
        ; jne =>failed
        ;; restore_rinsn_and_return(out)
    );
    start
}

extern "sysv64" fn load<T: crate::aligned_memory::Pod + Into<u64>, C: ContextObject>(
    vm: &mut EbpfVm<C>,
    vm_addr: u64,
    meter: &mut MeterSlots,
) -> HostCallResult {
    if let Some(rax) = vm.memory().load_first_attempt::<T>(vm_addr) {
        return HostCallResult {
            rax,
            dl: HostCallStatus::Ok,
        };
    }
    // The access violation handler may consume from the budget, so the VM needs to know how much
    // of it has been used up so far.
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

extern "sysv64" fn store<T: crate::aligned_memory::Pod, C: ContextObject>(
    vm: &mut EbpfVm<C>,
    vm_addr: u64,
    value: u64,
    meter: &mut MeterSlots,
) -> HostCallResult {
    const { assert!(cfg!(target_endian = "little")) };
    // SAFETY:
    //
    // Contract from `mem::transmute_copy`: This function will unsafely assume the pointer `src` is
    // valid for `size_of::<Dst>` bytes by transmuting `&Src` to `&Dst` and then reading the `&Dst`
    // (except that this is done in a way that is correct even when `&Dst` has stricter alignment
    // requirements than `&Src`).
    //
    // Contract from `mem::transmute_copy`: This function triggers undefined behavior if `Dst` is
    // larger than `Src`.
    //
    // Evidence: `store` is only instantiated for `u8`, `u16`, `u32` and `u64` (see
    // `generate_store`), which are not larger than `u64`, and for which any bytes are a
    // valid value. `&value` is valid for 8 bytes, of which the first `size_of::<T>()` are read,
    // which on little endian are the low ones, so the value is truncated as intended.
    let value = unsafe { std::mem::transmute_copy::<u64, T>(&value) };
    if vm.memory().store_first_attempt::<T>(value, vm_addr) {
        return HostCallResult {
            rax: 0,
            dl: HostCallStatus::Ok,
        };
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

//! The helpers for loads and stores.

use super::*;
use crate::memory_region::MemoryMapping;
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

/// The second attempts of the memory [`SupportEntry`]s, for when the first one (see
/// [`FirstAttempts`]) fails, as the access violation handler depends on the [`ContextObject`].
///
/// See [`Frame::memory_functions`].
#[repr(C)]
pub(in crate::codegen) struct MemoryFunctions<C: ContextObject> {
    load: [extern "sysv64" fn(&mut EbpfVm<C>, u64, &mut MeterSlots) -> HostCallResult; 4],
    store: [extern "sysv64" fn(&mut EbpfVm<C>, u64, u64, &mut MeterSlots) -> HostCallStatus; 4],
}

impl<C: ContextObject> MemoryFunctions<C> {
    const FUNCTIONS: Self = Self {
        load: [
            load_slow::<u8, C>,
            load_slow::<u16, C>,
            load_slow::<u32, C>,
            load_slow::<u64, C>,
        ],
        store: [
            store_slow::<u8, C>,
            store_slow::<u16, C>,
            store_slow::<u32, C>,
            store_slow::<u64, C>,
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
    let slow = out.new_dynamic_label();
    let first_attempt = FirstAttempts::LOAD[size as usize] as *const u8 as i64;
    let offset = size.load_offset();
    save_rinsn(out);
    push_for_sysv64_call(out);
    x64asm!(out
        ;; vm_address(out, frame_operand(0))
        ; mov rdi, [BYTE frame!(memory) + rbp]
        ; mov rax, QWORD first_attempt
        ;; debug_assert_sysv64_call_stack_alignment(out)
        ; call rax
        ; test dl, dl
        ; jz =>slow
        ;; pop_after_sysv64_call(out)
        ; mov RTEMP, rax
        ;; restore_rinsn_and_return(out)

        ; =>slow
        ;; reload_next_insn(out)
        ;; vm_address(out, frame_operand(0))
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
    let slow = out.new_dynamic_label();
    let first_attempt = FirstAttempts::STORE[size as usize] as *const u8 as i64;
    let offset = size.store_offset();
    let address = frame_operand(usize::from(from_register));
    // The value into `rdx`, and the address into `rsi`.
    let operands = |out: &mut Asm| {
        if from_register {
            x64asm!(out; mov rdx, [BYTE frame_operand(0) + rbp]);
        } else {
            x64asm!(out; movsxd rdx, DWORD [RTEMP - 4]);
        }
        vm_address(out, address);
    };
    save_rinsn(out);
    push_for_sysv64_call(out);
    x64asm!(out
        ;; operands(out)
        ; mov rdi, [BYTE frame!(memory) + rbp]
        ; mov rax, QWORD first_attempt
        ;; debug_assert_sysv64_call_stack_alignment(out)
        ; call rax
        ; test al, al
        ; jz =>slow
        ;; pop_after_sysv64_call(out)
        ;; restore_rinsn_and_return(out)

        ; =>slow
        ;; reload_next_insn(out)
        ;; operands(out)
        ; mov rdi, [BYTE frame!(vm) + rbp]
        // SUBTLE: `rcx` is `RTEMP`, which is not needed anymore.
        ; lea rcx, [ BYTE MeterSlots::OFFSET_FROM_RSP + rsp ]
        ; mov rax, [BYTE frame!(memory_functions) + rbp]
        ; mov rax, [ BYTE offset + rax ]
        ;; debug_assert_sysv64_call_stack_alignment(out)
        ; call rax
        ; cmp al, HostCallStatus::Ok as i8
        ;; pop_after_sysv64_call(out)
        ; jne =>failed
        ;; restore_rinsn_and_return(out)
    );
    start
}

/// `rsi` = the address operand at `operand` plus the offset of the instruction preceding the
/// address in `RTEMP`.
fn vm_address(out: &mut Asm, operand: i8) {
    x64asm!(out
        ; movsx rsi, WORD [RTEMP - 6]
        ; add rsi, [BYTE operand + rbp]
    );
}

/// Restore `RTEMP` from where [`push_for_sysv64_call`] saved it, after a call clobbered it.
fn reload_next_insn(out: &mut Asm) {
    let next_insn = MeterSlots::OFFSET_FROM_RSP
        .checked_add(std::mem::offset_of!(MeterSlots, next_insn) as i8)
        .unwrap();
    x64asm!(out; mov RTEMP, [ BYTE next_insn + rsp ]);
}

/// The first attempts of the loads and stores, which the memory supports call directly: they do
/// not depend on the [`ContextObject`], and only get the arguments they need, so that the compiler
/// has the registers to spare to not have to save any for them.
struct FirstAttempts;

impl FirstAttempts {
    const LOAD: [extern "sysv64" fn(&mut MemoryMapping, u64) -> FirstLoad; 4] = [
        load_first_attempt::<u8>,
        load_first_attempt::<u16>,
        load_first_attempt::<u32>,
        load_first_attempt::<u64>,
    ];
    const STORE: [extern "sysv64" fn(&mut MemoryMapping, u64, u64) -> bool; 4] = [
        store_first_attempt::<u8>,
        store_first_attempt::<u16>,
        store_first_attempt::<u32>,
        store_first_attempt::<u64>,
    ];
}

/// Returned by [`load_first_attempt`], in the registers the fields are named after.
#[repr(C)]
struct FirstLoad {
    rax: u64,
    /// Whether the load happened, and `rax` is what it loaded.
    dl: bool,
}

extern "sysv64" fn load_first_attempt<T: crate::aligned_memory::Pod + Into<u64>>(
    memory: &mut MemoryMapping,
    vm_addr: u64,
) -> FirstLoad {
    match memory.load_first_attempt::<T>(vm_addr) {
        Some(rax) => FirstLoad { rax, dl: true },
        None => FirstLoad { rax: 0, dl: false },
    }
}

/// The load for when [`load_first_attempt`] failed.
extern "sysv64" fn load_slow<T: crate::aligned_memory::Pod + Into<u64>, C: ContextObject>(
    vm: &mut EbpfVm<C>,
    vm_addr: u64,
    meter: &mut MeterSlots,
) -> HostCallResult {
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

/// The types that the stores are done in.
trait StoreValue: crate::aligned_memory::Pod {
    /// The low bits of `value`.
    fn truncate(value: u64) -> Self;
}

macro_rules! store_value {
    ($($ty:ty),*) => {$(
        impl StoreValue for $ty {
            #[inline(always)]
            fn truncate(value: u64) -> Self {
                value as $ty
            }
        }
    )*};
}

store_value!(u8, u16, u32, u64);

/// Whether the store happened.
extern "sysv64" fn store_first_attempt<T: StoreValue>(
    memory: &mut MemoryMapping,
    vm_addr: u64,
    value: u64,
) -> bool {
    memory.store_first_attempt::<T>(T::truncate(value), vm_addr)
}

/// The store for when [`store_first_attempt`] failed.
///
/// Returns just the status (in `al`), as there is no result.
extern "sysv64" fn store_slow<T: StoreValue, C: ContextObject>(
    vm: &mut EbpfVm<C>,
    vm_addr: u64,
    value: u64,
    meter: &mut MeterSlots,
) -> HostCallStatus {
    if !meter.hand_over_to_vm(vm) {
        return HostCallStatus::Failed;
    }
    let encrypted_vm = vm.encrypted_host_address();
    vm.memory()
        .store_second_attempt::<T, C>(T::truncate(value), vm_addr, encrypted_vm);
    meter.take_back_from_vm(vm);
    HostCallResult::of_program_result(vm).dl
}

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

/// The [`MemoryHelpers`] call these, as the access violation handler depends on the
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

/// The helpers for loads and stores.
pub(in crate::codegen) struct MemoryHelpers {
    /// One version for each access size, destination and source register combo.
    load: [[[u32; Reg::COUNT]; Reg::COUNT]; 4],
    /// Stores of the immediate.
    ///
    /// One version for each access size and destination register combo.
    store_imm: [[u32; Reg::COUNT]; 4],
    /// One version for each access size, destination and source register.
    store_reg: [[[u32; Reg::COUNT]; Reg::COUNT]; 4],
}

impl MemoryHelpers {
    /// Add the name and address of each helper to `symbols`.
    #[cfg(feature = "codegen-debug")]
    pub(super) fn debug_symbols(&self, symbols: &mut Vec<(String, usize)>) {
        for (size_log2, bits) in [8, 16, 32, 64].iter().copied().enumerate() {
            for dst in 0..Reg::COUNT {
                let store_imm = self.store_imm[size_log2][dst];
                symbols.push((format!("store_imm_u{bits}_r{dst}"), store_imm as usize));
                for src in 0..Reg::COUNT {
                    let load = self.load[size_log2][dst][src];
                    symbols.push((format!("load_u{bits}_r{dst}_r{src}"), load as usize));
                    let store_reg = self.store_reg[size_log2][dst][src];
                    symbols.push((
                        format!("store_reg_u{bits}_r{dst}_r{src}"),
                        store_reg as usize,
                    ));
                }
            }
        }
    }

    pub(in crate::codegen) fn load(&self, size: AccessSize, dst: Reg, src: Reg) -> u32 {
        self.load[size as usize][usize::from(dst.0)][usize::from(src.0)]
    }

    pub(in crate::codegen) fn store_imm(&self, size: AccessSize, dst: Reg) -> u32 {
        self.store_imm[size as usize][usize::from(dst.0)]
    }

    pub(in crate::codegen) fn store_reg(&self, size: AccessSize, dst: Reg, src: Reg) -> u32 {
        self.store_reg[size as usize][usize::from(dst.0)][usize::from(src.0)]
    }

    pub(super) fn generate(out: &mut Asm, base: u32) -> Self {
        let mut load = [[[0; Reg::COUNT]; Reg::COUNT]; 4];
        let mut store_imm = [[0; Reg::COUNT]; 4];
        let mut store_reg = [[[0; Reg::COUNT]; Reg::COUNT]; 4];
        let failed = out.new_dynamic_label();
        for size in AccessSize::ALL {
            let z = size as usize;
            for dst in Reg::ALL {
                let d = usize::from(dst.0);
                store_imm[z][d] = Self::generate_store(out, base, size, dst, None, failed);
                for src in Reg::ALL {
                    let s = usize::from(src.0);
                    load[z][d][s] = Self::generate_load(out, base, size, dst, src, failed);
                    store_reg[z][d][s] =
                        Self::generate_store(out, base, size, dst, Some(src), failed);
                }
            }
        }
        x64asm!(out
            ; =>failed
            // Running out of budget takes precedence over the memory error.
            ;; validate_meter(out)
            ;; terminate(out, SIG_PROGRAM_RESULT)
        );
        Self {
            load,
            store_imm,
            store_reg,
        }
    }

    /// Load `size` bytes into `dst` from the address in `src` plus the offset of the instruction
    /// preceding the address in `RTEMP`. Jumps to `failed` if the access fails.
    fn generate_load(
        out: &mut Asm,
        base: u32,
        size: AccessSize,
        dst: Reg,
        src: Reg,
        failed: DynamicLabel,
    ) -> u32 {
        let start = address(out, base, true);
        let offset = size.load_offset();
        push_for_sysv64_call(out);
        x64asm!(out
            ; mov rsi, Rq(src)
            ; movsx rdx, WORD [RTEMP - 6]
            ; add rsi, rdx
            ; mov rdi, rbp => Frame[BYTE -1].vm
            ; lea rdx, [ BYTE MeterSlots::OFFSET_FROM_RSP + rsp ]
            ; mov rax, rbp => Frame[BYTE -1].memory_functions
            ; mov rax, [ BYTE offset + rax ]
            ;; debug_assert_sysv64_call_stack_alignment(out)
            ; call rax
            ; cmp dl, HostCallStatus::Ok as i8
            ;; pop_after_sysv64_call(out)
            // SUBTLE: `dst` may be one of the popped registers above, so moving the result of load
            // into `dst` must come after.
            ; mov Rq(dst), rax
            ; jne =>failed
            ; ret
        );
        start
    }

    /// Store `size` bytes of `src` (or of the immediate), to the address in `dst` plus offset.
    /// Jumps to `failed` if the access fails.
    fn generate_store(
        out: &mut Asm,
        base: u32,
        size: AccessSize,
        dst: Reg,
        src: Option<Reg>,
        failed: DynamicLabel,
    ) -> u32 {
        let start = address(out, base, true);
        let offset = size.store_offset();
        push_for_sysv64_call(out);
        // SUBTLE: `rsi` may be `src`, but is also the argument we pass to the sysv64 function.
        match src {
            Some(src) => x64asm!(out; mov rdx, Rq(src)),
            None => x64asm!(out; movsxd rdx, DWORD [RTEMP - 4]),
        }
        x64asm!(out
            ; mov rsi, Rq(dst)
            ; movsx rdi, WORD [RTEMP - 6]
            ; add rsi, rdi
            ; mov rdi, rbp => Frame[BYTE -1].vm
            ; lea rcx, [ BYTE MeterSlots::OFFSET_FROM_RSP + rsp ]
            ; mov rax, rbp => Frame[BYTE -1].memory_functions
            ; mov rax, [ BYTE offset + rax ]
            ;; debug_assert_sysv64_call_stack_alignment(out)
            ; call rax
            ; cmp dl, HostCallStatus::Ok as i8
            ;; pop_after_sysv64_call(out)
            ; jne =>failed
            ; ret
        );
        start
    }
}

extern "sysv64" fn load<T: crate::aligned_memory::Pod + Into<u64>, C: ContextObject>(
    vm: &mut EbpfVm<C>,
    vm_addr: u64,
    meter: &mut MeterSlots,
) -> HostCallResult {
    if let result @ crate::error::ProgramResult::Ok(_) =
        vm.memory().load_first_attempt::<T>(vm_addr)
    {
        return HostCallResult::new(result, &mut vm.program_result);
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
    // `MemoryHelpers::generate_store`), which are not larger than `u64`, and for which any bytes are a
    // valid value. `&value` is valid for 8 bytes, of which the first `size_of::<T>()` are read,
    // which on little endian are the low ones, so the value is truncated as intended.
    let value = unsafe { std::mem::transmute_copy::<u64, T>(&value) };
    if let result @ crate::error::ProgramResult::Ok(_) =
        vm.memory().store_first_attempt::<T>(value, vm_addr)
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

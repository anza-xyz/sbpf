//! The helpers for loads and stores.

use super::*;

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

    fn load_function(self) -> *const u8 {
        match self {
            Self::B => load::<u8> as *const u8,
            Self::H => load::<u16> as *const u8,
            Self::W => load::<u32> as *const u8,
            Self::DW => load::<u64> as *const u8,
        }
    }

    fn store_function(self) -> *const u8 {
        match self {
            Self::B => store::<u8> as *const u8,
            Self::H => store::<u16> as *const u8,
            Self::W => store::<u32> as *const u8,
            Self::DW => store::<u64> as *const u8,
        }
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
        let function = size.load_function();
        push_for_sysv64_call(out);
        x64asm!(out
            ; mov rsi, Rq(src)
            ; movsx rdx, WORD [RTEMP - 6]
            ; add rsi, rdx
            ; mov rax, rbp => Frame[BYTE -1].vm
            ; mov rdi, rax => Vm.memory_mapping
            ; lea rdx, rax => Vm.program_result
            ; mov rax, QWORD function as i64
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
        let function = size.store_function();
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
            ; mov rax, rbp => Frame[BYTE -1].vm
            ; mov rdi, rax => Vm.memory_mapping
            ; lea rcx, rax => Vm.program_result
            ; mov rax, QWORD function as i64
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

extern "sysv64" fn load<T: crate::aligned_memory::Pod + Into<u64>>(
    mapping: &mut crate::memory_region::MemoryMapping,
    vm_addr: u64,
    result: &mut crate::error::ProgramResult,
) -> HostCallResult {
    let loaded = match mapping.load_first_attempt::<T>(vm_addr) {
        crate::error::ProgramResult::Err(_) => mapping.load_second_attempt::<T>(vm_addr),
        loaded => loaded,
    };
    HostCallResult::new(loaded, result)
}

extern "sysv64" fn store<T: crate::aligned_memory::Pod>(
    mapping: &mut crate::memory_region::MemoryMapping,
    vm_addr: u64,
    value: u64,
    result: &mut crate::error::ProgramResult,
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
    let stored = match mapping.store_first_attempt::<T>(value, vm_addr) {
        crate::error::ProgramResult::Err(_) => mapping.store_second_attempt::<T>(value, vm_addr),
        stored => stored,
    };
    HostCallResult::new(stored, result)
}

//! The helpers for loads and stores.

use super::*;
use crate::codegen::host::AccessSize;
#[cfg(doc)]
use crate::codegen::host::MeterSlots;

/// Where [`push_for_sysv64_call`] leaves the [`MeterSlots`] relative to `rsp`.
const METER_SLOTS_OFFSET_FROM_RSP: i8 = (BPF_SYSV64_CLOBBERED.count_ones() * 8) as i8;

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
        let offset = i8::try_from(size.load_offset()).unwrap();
        push_for_sysv64_call(out);
        x64asm!(out
            ; mov rsi, Rq(src)
            ; movsx rdx, WORD [RTEMP - 6]
            ; add rsi, rdx
            ; mov rdi, rbp => Frame[BYTE -1].vm
            ; lea rdx, [ BYTE METER_SLOTS_OFFSET_FROM_RSP + rsp ]
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
        let offset = i8::try_from(size.store_offset()).unwrap();
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
            ; lea rcx, [ BYTE METER_SLOTS_OFFSET_FROM_RSP + rsp ]
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

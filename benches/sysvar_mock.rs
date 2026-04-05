// Copyright 2020 Solana Maintainers <maintainers@solana.com>
//
// Licensed under the Apache License, Version 2.0 <http://www.apache.org/licenses/LICENSE-2.0> or
// the MIT license <http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

#![feature(test)]

extern crate solana_sbpf;
extern crate test;

use solana_sbpf::{
    declare_builtin_function, ebpf,
    elf::Section,
    error::EbpfError,
    memory_region::{AccessType, MemoryMapping, MemoryRegion},
    program::{BuiltinProgram, SBPFVersion},
    verifier::RequisiteVerifier,
    vm::{Config, ContextObject, ExecutionMode},
};
use std::{slice::from_raw_parts_mut, sync::Arc};
use test::Bencher;
use test_utils::{create_vm, TestContextObject};

static SYSVAR_VALUE: [u8; 32] = [
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25,
    26, 27, 28, 29, 30, 31,
];

fn bench_jit_vs_interpreter(bencher: &mut Bencher, assembly: &str, instruction_meter: u64) {
    let config = Config {
        enabled_sbpf_versions: SBPFVersion::V3..=SBPFVersion::V3,
        aligned_memory_mapping: true,
        ..Config::default()
    };
    let mut loader = BuiltinProgram::new_loader(config);
    let _ = <SyscallSysvar as solana_sbpf::program::BuiltinFunctionDefinition<_>>::register(
        &mut loader,
        "sysvar",
    )
    .unwrap();
    let loader = Arc::new(loader);
    let mut mem = [0u8; 0x3000];
    mem[0x2A00..0x2A20].copy_from_slice(&SYSVAR_VALUE);
    let mut executable =
        solana_sbpf::assembler::assemble::<TestContextObject>(assembly, Arc::clone(&loader))
            .unwrap();
    executable.ro_section = Section::Owned(ebpf::MM_RODATA_START as usize, mem.to_vec());
    executable.verify::<RequisiteVerifier>().unwrap();
    executable.jit_compile().unwrap();
    let mut context_object = TestContextObject::default();
    let mem_region = MemoryRegion::new_writable(&mut mem, ebpf::MM_INPUT_START);
    create_vm!(
        vm,
        &executable,
        &mut context_object,
        stack,
        heap,
        vec![mem_region],
        None
    );
    /*let interpreter_summary = bencher
    .bench(|bencher| {
        bencher.iter(|| {
            unsafe {
                vm.context_object_pointer.as_mut().remaining = instruction_meter;
            }
            let (instruction_count_interpreter, result) =
                vm.execute_program(&executable, &mut ExecutionMode::Interpreted);
            assert!(result.is_ok(), "{:?}", result);
            assert_eq!(instruction_count_interpreter, instruction_meter);
        });
        Ok(())
    })
    .unwrap()
    .unwrap();*/
    let jit_summary = bencher
        .bench(|bencher| {
            bencher.iter(|| {
                unsafe {
                    vm.context_object_pointer.as_mut().remaining = instruction_meter;
                }
                let (instruction_count_jit, result) =
                    vm.execute_program(&executable, &mut ExecutionMode::Jit);
                assert!(result.is_ok(), "{:?}", result);
                assert_eq!(instruction_count_jit, instruction_meter);
            });
            Ok(())
        })
        .unwrap()
        .unwrap();
    /*println!(
        "jit_vs_interpreter_ratio={}",
        interpreter_summary.mean / jit_summary.mean
    );*/
}

declare_builtin_function!(
    SyscallSysvar,
    fn rust(
        context_object: &mut TestContextObject,
        sysvar_id_addr: u64,
        var_addr: u64,
        offset: u64,
        length: u64,
        _arg5: u64,
        memory_mapping: &mut MemoryMapping,
    ) -> Result<u64, Box<dyn std::error::Error>> {
        const MEM_OP_BASE_COST: u64 = 10;
        const SYSVAR_BASE_COST: u64 = 100;
        const CPI_BYTES_PER_UNIT: u64 = 250;
        let sysvar_id_cost = 32_u64.checked_div(CPI_BYTES_PER_UNIT).unwrap_or(0);
        let sysvar_buf_cost = length.checked_div(CPI_BYTES_PER_UNIT).unwrap_or(0);
        let cu_price = SYSVAR_BASE_COST
            .saturating_add(sysvar_id_cost)
            .saturating_add(std::cmp::max(sysvar_buf_cost, MEM_OP_BASE_COST));
        if context_object.get_remaining() < cu_price {
            return Err(Box::new(EbpfError::ExceededMaxInstructions));
        }
        context_object.consume(cu_price);
        if sysvar_id_addr != 42 || offset != 0 || length != 32 {
            return Err(Box::new(EbpfError::UnsupportedInstruction));
        }
        let var_ptr: Result<u64, EbpfError> = memory_mapping
            .map(AccessType::Store, var_addr, length)
            .into();
        let var_slice = unsafe { from_raw_parts_mut(var_ptr? as *mut u8, length as usize) };
        var_slice.copy_from_slice(&SYSVAR_VALUE);
        Ok(0)
    }
);

#[bench]
fn bench_sysvar_control(bencher: &mut Bencher) {
    bench_jit_vs_interpreter(
        bencher,
        "
        exit",
        1,
    );
}

#[bench]
fn bench_sysvar_static_address_translation(bencher: &mut Bencher) {
    bench_jit_vs_interpreter(
        bencher,
        "
        lddw r0, 0x000002A00
        ldxdw r1, [r0 + 0]
        ldxdw r2, [r0 + 8]
        ldxdw r3, [r0 + 16]
        ldxdw r4, [r0 + 24]
        exit",
        6,
    );
}

#[bench]
fn bench_sysvar_dynamic_address_translation(bencher: &mut Bencher) {
    bench_jit_vs_interpreter(
        bencher,
        "
        lddw r0, 0x400002A00
        ldxdw r1, [r0 + 0]
        ldxdw r2, [r0 + 8]
        ldxdw r3, [r0 + 16]
        ldxdw r4, [r0 + 24]
        exit",
        6,
    );
}

#[bench]
fn bench_sysvar_syscall(bencher: &mut Bencher) {
    bench_jit_vs_interpreter(
        bencher,
        "
        mov r1, 0x2A
        lddw r2, 0x200000000
        mov r3, 0
        mov r4, 32
        syscall sysvar
        ldxdw r1, [r2 + 0]
        ldxdw r3, [r2 + 16]
        ldxdw r4, [r2 + 24]
        ldxdw r2, [r2 + 8]
        exit",
        120,
    );
}

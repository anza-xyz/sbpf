// Copyright 2020 Solana Maintainers <maintainers@solana.com>
//
// Licensed under the Apache License, Version 2.0 <http://www.apache.org/licenses/LICENSE-2.0> or
// the MIT license <http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

extern crate solana_sbpf;

use criterion::{criterion_group, criterion_main, Criterion};
use solana_sbpf::{
    assembler::assemble,
    ebpf,
    elf::Executable,
    memory_region::MemoryRegion,
    program::{BuiltinProgram, SBPFVersion},
    verifier::RequisiteVerifier,
    vm::{CallFrame, Config, ExecutionMode},
};
use std::{fs::File, io::Read, sync::Arc};
use test_utils::{create_vm, TestContextObject};

fn bench_backends(
    c: &mut Criterion,
    name: &str,
    executable: &Executable<TestContextObject>,
    instruction_meter: u64,
    expected_instruction_count: u64,
    mem: *mut [u8],
) {
    let mut context_object = TestContextObject::default();
    let mem_region = MemoryRegion::new(mem, ebpf::MM_INPUT_START);
    create_vm!(
        vm,
        executable,
        &mut context_object,
        stack,
        heap,
        vec![mem_region],
        None
    );
    let mut call_frames = vec![CallFrame::default(); Config::default().max_call_depth];
    // Each run starts from the same registers, which the backends may leave behind differently.
    let registers = vm.registers;
    let mut group = c.benchmark_group(name);
    let mut bench = |id: &str, mut mode: ExecutionMode, call_frames: &mut [CallFrame]| {
        group.bench_function(id, |b| {
            b.iter(|| {
                vm.registers = registers;
                vm.context().remaining = instruction_meter;
                let (instruction_count, result) =
                    vm.execute_program(executable, &mut mode, call_frames);
                assert!(result.is_ok(), "{:?}", result);
                assert_eq!(instruction_count, expected_instruction_count);
            })
        });
    };
    bench("interpreter", ExecutionMode::Interpreted, &mut call_frames);
    #[cfg(all(feature = "jit", not(target_os = "windows"), target_arch = "x86_64"))]
    {
        executable.jit_compile().unwrap();
        bench("jit", ExecutionMode::Jit, &mut []);
    }
    group.finish();
}

fn bench_assembly(
    c: &mut Criterion,
    name: &str,
    assembly: &str,
    config: Config,
    instruction_meter: u64,
    mem: *mut [u8],
) {
    let executable =
        assemble::<TestContextObject>(assembly, Arc::new(BuiltinProgram::new_loader(config)))
            .unwrap();
    executable.verify::<RequisiteVerifier>().unwrap();
    bench_backends(
        c,
        name,
        &executable,
        instruction_meter,
        instruction_meter,
        mem,
    );
}

fn bench_init_start(c: &mut Criterion) {
    let mut file = File::open("tests/elfs/rodata_section_sbpfv0.so").unwrap();
    let mut elf = Vec::new();
    file.read_to_end(&mut elf).unwrap();
    let executable =
        Executable::<TestContextObject>::from_elf(&elf, Arc::new(BuiltinProgram::new_mock()))
            .unwrap();
    executable.verify::<RequisiteVerifier>().unwrap();
    bench_backends(c, "init_start", &executable, 37, 3, &mut []);
}

fn bench_address_translation(c: &mut Criterion) {
    bench_assembly(
        c,
        "address_translation",
        "
    add64 r10, 0
    ldxb r0, [r1]
    add r1, 1
    mov r0, r1
    and r0, 0xFFFFFF
    jlt r0, 0x20000, -5
    exit",
        Config::default(),
        655362,
        &mut [0; 0x20000],
    );
}

static ADDRESS_TRANSLATION_STACK_CODE: &str = "
    add64 r10, 4096
    mov r1, r2
    and r1, 4095
    mov r3, r10
    sub r3, r1
    add r3, -1
    ldxb r4, [r3]
    add r2, 1
    jlt r2, 0x10000, -8
    exit";

fn bench_address_translation_stack_fixed(c: &mut Criterion) {
    bench_assembly(
        c,
        "address_translation_stack_fixed",
        ADDRESS_TRANSLATION_STACK_CODE,
        Config {
            enabled_sbpf_versions: SBPFVersion::V0..=SBPFVersion::V0,
            ..Config::default()
        },
        524290,
        &mut [],
    );
}

fn bench_address_translation_stack_dynamic(c: &mut Criterion) {
    bench_assembly(
        c,
        "address_translation_stack_dynamic",
        ADDRESS_TRANSLATION_STACK_CODE,
        Config::default(),
        524290,
        &mut [],
    );
}

fn bench_empty_for_loop(c: &mut Criterion) {
    bench_assembly(
        c,
        "empty_for_loop",
        "
    add64 r10, 0
    mov r1, r2
    and r1, 1023
    add r2, 1
    jlt r2, 0x10000, -4
    exit",
        Config::default(),
        262146,
        &mut [0; 0],
    );
}

fn bench_call_depth_fixed(c: &mut Criterion) {
    bench_assembly(
        c,
        "call_depth_fixed",
        "
    mov r6, 0
    add r6, 1
    mov r1, 18
    call function_foo
    jlt r6, 1024, -4
    exit
    function_foo:
    stw [r10-4], 0x11223344
    mov r6, r1
    jgt r6, 0, +1
    exit
    mov r1, r6
    add r1, -1
    call function_foo
    exit",
        Config {
            enabled_sbpf_versions: SBPFVersion::V0..=SBPFVersion::V0,
            ..Config::default()
        },
        137218,
        &mut [],
    );
}

fn bench_call_depth_dynamic(c: &mut Criterion) {
    bench_assembly(
        c,
        "call_depth_dynamic",
        "
    add64 r10, 0
    mov r6, 0
    add r6, 1
    mov r1, 18
    call function_foo
    jlt r6, 1024, -4
    exit
    function_foo:
    add r10, 64
    stw [r10-4], 0x11223344
    mov r6, r1
    jeq r6, 0, +3
    mov r1, r6
    add r1, -1
    call function_foo
    exit",
        Config::default(),
        156675,
        &mut [],
    );
}

fn bench_mem_ldxdw(c: &mut Criterion) {
    let config = Config {
        enabled_sbpf_versions: SBPFVersion::V0..=SBPFVersion::V0,
        ..Config::default()
    };
    const LOAD64_ITERATIONS: u64 = 65536;
    const LOAD64_INSTRUCTION_COUNT: u64 = LOAD64_ITERATIONS * 3 + 2;
    let assembly = format!(
        r#"
            entrypoint:
            mov r2, {}
            loop:
            ldxdw r0, [r1+0]
            add r2, -1
            jgt r2, 0, loop
            exit
        "#,
        LOAD64_ITERATIONS
    );
    bench_assembly(
        c,
        "mem_ldxdw",
        &assembly,
        config,
        LOAD64_INSTRUCTION_COUNT,
        &mut [0u8; 8],
    );
}

criterion_group!(
    benches,
    bench_init_start,
    bench_address_translation,
    bench_address_translation_stack_fixed,
    bench_address_translation_stack_dynamic,
    bench_empty_for_loop,
    bench_call_depth_fixed,
    bench_call_depth_dynamic,
    bench_mem_ldxdw,
);
criterion_main!(benches);

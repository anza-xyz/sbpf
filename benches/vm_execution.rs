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
    program::{BuiltinFunctionDefinition, BuiltinProgram, SBPFVersion},
    verifier::RequisiteVerifier,
    vm::{CallFrame, Config, ExecutionMode},
};
use std::{fs::File, io::Read, sync::Arc};
use test_utils::{create_vm, syscalls, TestContextObject};

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
        r#"
        add64 r10, 0
        ldxb r0, [r1]
        add r1, 1
        mov r0, r1
        and r0, 0xFFFFFF
        jlt r0, 0x20000, -5
        exit
        "#,
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
        r#"
        add64 r10, 0
        mov r1, r2
        and r1, 1023
        add r2, 1
        jlt r2, 0x10000, -4
        exit
        "#,
        Config::default(),
        262146,
        &mut [0; 0],
    );
}

fn bench_call_depth_fixed(c: &mut Criterion) {
    bench_assembly(
        c,
        "call_depth_fixed",
        r#"
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
        exit
        "#,
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
        r#"
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
        exit
        "#,
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

/// Assembles `assembly` for each version and benches it with whatever instruction count the
/// interpreter arrives at, so that kernels may branch on data.
fn bench_compute(c: &mut Criterion, name: &str, assembly: &str, mem: *mut [u8]) {
    bench_versions(c, &format!("compute/{name}"), assembly, |_| {}, mem);
}

/// `bench_compute` with the syscalls `register` registers in the loader.
fn bench_versions(
    c: &mut Criterion,
    name: &str,
    assembly: &str,
    register: fn(&mut BuiltinProgram<TestContextObject>),
    mem: *mut [u8],
) {
    for version in [SBPFVersion::V0, SBPFVersion::V3] {
        let config = Config {
            enabled_sbpf_versions: version..=version,
            ..Config::default()
        };
        let mut loader = BuiltinProgram::new_loader(config);
        register(&mut loader);
        let executable = assemble::<TestContextObject>(assembly, Arc::new(loader)).unwrap();
        executable.verify::<RequisiteVerifier>().unwrap();
        let mut context_object = TestContextObject::new(u64::MAX);
        let mem_region = MemoryRegion::new(mem, ebpf::MM_INPUT_START);
        create_vm!(
            vm,
            &executable,
            &mut context_object,
            stack,
            heap,
            vec![mem_region],
            None
        );
        let mut call_frames = vec![CallFrame::default(); Config::default().max_call_depth];
        let (instruction_count, result) = vm.execute_program(
            &executable,
            &mut ExecutionMode::Interpreted,
            &mut call_frames,
        );
        assert!(result.is_ok(), "{:?}", result);
        bench_backends(
            c,
            &format!("{name}/{version:?}").to_lowercase(),
            &executable,
            instruction_count,
            instruction_count,
            mem,
        );
    }
}

/// Independent chains of ALU operations with immediate operands, on 64-bit registers or on
/// 32-bit subregisters.
fn bench_compute_alu_imm(c: &mut Criterion) {
    for (name, suffix) in [("alu64_imm", ""), ("alu32_imm", "32")] {
        let assembly = format!(
            r#"
            mov r9, 0x8000
            loop:
            add{s} r1, 0x1234
            xor{s} r2, 0x5a5a5a5a
            lsh{s} r3, 3
            rsh{s} r4, 1
            or{s} r5, 0x100
            and{s} r1, 0x7fffffff
            sub{s} r2, 77
            arsh{s} r3, 2
            mul{s} r4, 3
            add{s} r5, -9
            xor{s} r1, -1
            or{s} r2, 0x10
            rsh{s} r3, 5
            add{s} r4, 0x7fff
            and{s} r5, 0xffff
            add r9, -1
            jne r9, 0, loop
            mov r0, r1
            add r0, r2
            add r0, r3
            add r0, r4
            add r0, r5
            exit
            "#,
            s = suffix
        );
        bench_compute(c, name, &assembly, &mut []);
    }
}

/// The same operations as `alu64_imm`, but with register operands, which need no immediates.
fn bench_compute_alu64_reg(c: &mut Criterion) {
    bench_compute(
        c,
        "alu64_reg",
        r#"
        mov r6, 0x1234
        mov r7, 3
        mov r8, 0x5a5a5a5a
        mov r9, 0x8000
        loop:
        add r1, r6
        xor r2, r8
        lsh r3, r7
        rsh r4, r7
        or r5, r6
        and r1, r8
        sub r2, r7
        arsh r3, r7
        mul r4, r7
        add r5, r8
        xor r1, r2
        or r2, r6
        rsh r3, r7
        add r4, r5
        and r5, r8
        add r9, -1
        jne r9, 0, loop
        mov r0, r1
        add r0, r2
        add r0, r3
        add r0, r4
        add r0, r5
        exit
        "#,
        &mut [],
    );
}

/// Divisions and remainders by immediates and by registers.
fn bench_compute_div_mod(c: &mut Criterion) {
    bench_compute(
        c,
        "div_mod",
        r#"
        mov r9, 0x8000
        loop:
        mov r1, r9
        lsh r1, 20
        mov r2, r1
        div r2, 7
        mov r3, r1
        mod r3, 13
        mov r4, r9
        or r4, 1
        mov r5, r1
        div r5, r4
        mod r1, r4
        div32 r2, 3
        mod32 r3, 5
        add r0, r1
        add r0, r2
        add r0, r3
        add r0, r5
        add r9, -1
        jne r9, 0, loop
        exit
        "#,
        &mut [],
    );
}

/// splitmix64, which multiplies by 64-bit constants loaded with `lddw` ahead of the loop.
fn bench_compute_splitmix64(c: &mut Criterion) {
    bench_compute(
        c,
        "splitmix64",
        r#"
        lddw r6, 0x9e3779b97f4a7c15
        lddw r7, 0xbf58476d1ce4e5b9
        lddw r8, 0x94d049bb133111eb
        mov r9, 0x8000
        loop:
        add r1, r6
        mov r2, r1
        mov r3, r2
        rsh r3, 30
        xor r2, r3
        mul r2, r7
        mov r3, r2
        rsh r3, 27
        xor r2, r3
        mul r2, r8
        mov r3, r2
        rsh r3, 31
        xor r2, r3
        xor r0, r2
        add r9, -1
        jne r9, 0, loop
        exit
        "#,
        &mut [],
    );
}

/// A four-way branch on xorshift64 output, so that taken branches are hard to predict.
fn bench_compute_branches(c: &mut Criterion) {
    bench_compute(
        c,
        "branches",
        r#"
        mov r1, 0x12345678
        mov r9, 0x8000
        loop:
        mov r2, r1
        lsh r2, 13
        xor r1, r2
        mov r2, r1
        rsh r2, 7
        xor r1, r2
        mov r2, r1
        lsh r2, 17
        xor r1, r2
        mov r3, r1
        and r3, 3
        jeq r3, 0, case0
        jeq r3, 1, case1
        jsgt r1, 0, case2
        add r0, 7
        ja next
        case0:
        add r0, 1
        ja next
        case1:
        xor r0, 0x55
        ja next
        case2:
        lsh r0, 1
        next:
        add r9, -1
        jne r9, 0, loop
        exit
        "#,
        &mut [],
    );
}

/// Spills to and reloads from the stack at various offsets and widths.
fn bench_compute_stack_offsets(c: &mut Criterion) {
    bench_compute(
        c,
        "stack_offsets",
        r#"
        mov r9, 0x8000
        loop:
        stxdw [r10-8], r9
        stxdw [r10-16], r0
        stxw [r10-20], r9
        stxh [r10-22], r9
        stxb [r10-23], r9
        stdw [r10-32], 0x1234
        stw [r10-36], -1
        ldxdw r1, [r10-16]
        ldxdw r2, [r10-8]
        ldxw r3, [r10-20]
        ldxh r4, [r10-22]
        ldxb r5, [r10-23]
        ldxdw r6, [r10-32]
        ldxw r7, [r10-36]
        add r1, r2
        add r1, r3
        add r1, r4
        add r1, r5
        add r1, r6
        add r1, r7
        mov r0, r1
        add r9, -1
        jne r9, 0, loop
        exit
        "#,
        &mut [],
    );
}

/// Sums the input region with an unrolled loop of loads at increasing offsets.
fn bench_compute_sum_input(c: &mut Criterion) {
    let mut mem = [0u8; 4096];
    for (i, byte) in mem.iter_mut().enumerate() {
        *byte = i as u8;
    }
    bench_compute(
        c,
        "sum_input",
        r#"
        mov r6, r1
        mov r9, 64
        outer:
        mov r1, r6
        mov r2, r6
        add r2, 4096
        inner:
        ldxdw r3, [r1+0]
        add r0, r3
        ldxdw r3, [r1+8]
        add r0, r3
        ldxdw r3, [r1+16]
        add r0, r3
        ldxdw r3, [r1+24]
        add r0, r3
        ldxdw r3, [r1+32]
        add r0, r3
        ldxdw r3, [r1+40]
        add r0, r3
        ldxdw r3, [r1+48]
        add r0, r3
        ldxdw r3, [r1+56]
        add r0, r3
        add r1, 64
        jlt r1, r2, inner
        add r9, -1
        jne r9, 0, outer
        exit
        "#,
        &mut mem,
    );
}

/// Loops over syscalls, alone and taking turns, with SBPFv0 dispatching them by hash and SBPFv3
/// statically.
fn bench_syscalls(c: &mut Criterion) {
    // A buffer to frob, followed by two equal strings to compare.
    let mut mem = *b"frobbed\0string\0string\0";
    let gather_bytes = r#"
        mov r1, 1
        mov r2, 2
        mov r3, 3
        mov r4, 4
        mov r5, 5
        syscall bpf_gather_bytes
    "#;
    let mem_frob = r#"
        mov r1, r7
        mov r2, 8
        syscall bpf_mem_frob
    "#;
    let str_cmp = r#"
        mov r1, r7
        add r1, 8
        mov r2, r7
        add r2, 16
        syscall bpf_str_cmp
    "#;
    for (name, body) in [
        ("gather_bytes", gather_bytes.to_string()),
        ("mem_frob", mem_frob.to_string()),
        ("str_cmp", str_cmp.to_string()),
        ("mixed", [gather_bytes, mem_frob, str_cmp].concat()),
    ] {
        let assembly = format!(
            r#"
            mov r6, 1000
            mov r7, r1
            loop:
            {body}
            add r6, -1
            jne r6, 0, loop
            exit
            "#
        );
        bench_versions(
            c,
            &format!("syscalls/{name}"),
            &assembly,
            |loader| {
                syscalls::SyscallGatherBytes::register(loader, "bpf_gather_bytes").unwrap();
                syscalls::SyscallMemFrob::register(loader, "bpf_mem_frob").unwrap();
                syscalls::SyscallStrCmp::register(loader, "bpf_str_cmp").unwrap();
            },
            &mut mem,
        );
    }
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
    bench_compute_alu_imm,
    bench_compute_alu64_reg,
    bench_compute_div_mod,
    bench_compute_splitmix64,
    bench_compute_branches,
    bench_compute_stack_offsets,
    bench_compute_sum_input,
    bench_syscalls,
);
criterion_main!(benches);

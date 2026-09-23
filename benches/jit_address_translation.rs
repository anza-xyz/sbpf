#![cfg_attr(
    all(feature = "jit", not(target_os = "windows"), target_arch = "x86_64"),
    feature(test)
)]
#![cfg(all(feature = "jit", not(target_os = "windows"), target_arch = "x86_64"))]

extern crate test;

use solana_sbpf::{
    assembler::assemble,
    ebpf,
    elf::Executable,
    memory_region::MemoryRegion,
    program::{BuiltinProgram, SBPFVersion},
    verifier::RequisiteVerifier,
    vm::{CallFrame, Config, ExecutionMode},
};
use std::{hint::black_box, sync::Arc};
use test::Bencher;
use test_utils::{create_vm, TestContextObject};

const BUDGET: u64 = 1_000_000;
const BODY_EXECUTIONS: usize = 16_384;
// Keep a modest code footprint while amortizing loop branches and VM entry.
const DEFAULT_SITES: usize = 128;

fn executable(assembly: &str, aligned: bool) -> Executable<TestContextObject> {
    let config = Config {
        enabled_sbpf_versions: SBPFVersion::V0..=SBPFVersion::V0,
        aligned_memory_mapping: aligned,
        stack_frame_size: 4096,
        // Retain the default instruction meter, immediate sanitization and NOPs.
        ..Config::default()
    };
    let executable = assemble(assembly, Arc::new(BuiltinProgram::new_loader(config))).unwrap();
    executable.verify::<RequisiteVerifier>().unwrap();
    executable
}

fn repeated_program(body: &str, sites: usize) -> (String, u64) {
    assert_eq!(BODY_EXECUTIONS % sites, 0);
    loop_program(&format!("{body}\n").repeat(sites), BODY_EXECUTIONS / sites)
}

fn loop_program(body: &str, loops: usize) -> (String, u64) {
    let assembly = format!(
        "mov64 r0, 0\nmov64 r3, {loops}\nmov64 r4, 0x12345678\nloop:\n{body}\n\
         sub64 r3, 1\njne r3, 0, loop\nexit",
    );
    let instruction_count = 4 + loops * (body.lines().count() + 2);
    (assembly, instruction_count as u64)
}

fn print_code_size(name: &str, executable: &Executable<TestContextObject>) {
    let compiled = executable.get_compiled_program().unwrap();
    println!(
        "{name}: guest_bytes={} code_bytes={} allocated_bytes={}",
        executable.get_text_bytes().1.len(),
        compiled.machine_code_length(),
        compiled.mem_size(),
    );
}

fn bench_execution(
    bencher: &mut Bencher,
    name: &str,
    program: (String, u64),
    aligned: bool,
    writable: bool,
    succeeds: bool,
) {
    let executable = executable(&program.0, aligned);
    executable.jit_compile().unwrap();
    print_code_size(name, &executable);

    let mut input = [0x5au8; 1024];
    let mut second = [0xa5u8; 1024];
    let input_region = if writable {
        MemoryRegion::new(&raw mut input[..], ebpf::MM_INPUT_START)
    } else {
        MemoryRegion::new(&raw const input[..], ebpf::MM_INPUT_START)
    };
    let mut context = TestContextObject::default();
    create_vm!(
        vm,
        &executable,
        &mut context,
        stack,
        heap,
        vec![
            input_region,
            MemoryRegion::new(
                &raw mut second[..],
                ebpf::MM_INPUT_START + ebpf::MM_REGION_SIZE
            ),
        ],
        None
    );
    vm.registers[2] = ebpf::MM_INPUT_START + ebpf::MM_REGION_SIZE;
    vm.registers[5] = ebpf::MM_STACK_START;
    vm.registers[6] = 8 * ebpf::MM_REGION_SIZE;
    let registers = vm.registers;
    for (i, byte) in stack.as_slice_mut().iter_mut().enumerate() {
        *byte = (i / 4096) as u8;
    }
    let initial_stack = stack.as_slice().to_vec();

    // Validate outside the timed loop, using identical initial registers and
    // backing memory. Compare the exact error and PC as well as CU and writes.
    let mut frames = vec![CallFrame::default(); executable.get_config().max_call_depth];
    vm.context().remaining = BUDGET;
    let expected = vm.execute_program(&executable, &mut ExecutionMode::Interpreted, &mut frames);
    assert_eq!(expected.1.is_ok(), succeeds);
    // Fault cases fail at the first body instruction, after three setup instructions.
    assert_eq!(expected.0, if succeeds { program.1 } else { 4 });
    let expected_remaining = vm.context().remaining;
    let expected_pc = vm.registers[11];
    let expected_input = input;
    let expected_second = second;
    let expected_stack = stack.as_slice().to_vec();

    input.fill(0x5a);
    second.fill(0xa5);
    stack.as_slice_mut().copy_from_slice(&initial_stack);
    vm.registers = registers;
    vm.context().remaining = BUDGET;
    let actual = vm.execute_program(&executable, &mut ExecutionMode::Jit, &mut []);
    assert_eq!(actual.0, expected.0);
    assert_eq!(format!("{:?}", actual.1), format!("{:?}", expected.1));
    assert_eq!(vm.context().remaining, expected_remaining);
    assert_eq!(vm.registers[11], expected_pc);
    assert_eq!(input, expected_input);
    assert_eq!(second, expected_second);
    assert_eq!(stack.as_slice(), expected_stack);

    bencher.iter(|| {
        vm.registers = registers;
        vm.context().remaining = BUDGET;
        black_box(vm.execute_program(&executable, &mut ExecutionMode::Jit, &mut []))
    });

    // Stores in these workloads are idempotent, so repeated timed executions
    // must leave the same memory as the validated interpreter execution.
    assert_eq!(input, expected_input);
    assert_eq!(second, expected_second);
    assert_eq!(stack.as_slice(), expected_stack);
    assert_eq!(vm.context().remaining, expected_remaining);
}

macro_rules! bench_memory {
    ($name:ident, $body:expr) => {
        bench_memory!($name, $body, true, true, true);
    };
    ($name:ident, $body:expr, $aligned:expr, $writable:expr, $succeeds:expr) => {
        #[bench]
        fn $name(bencher: &mut Bencher) {
            bench_execution(
                bencher,
                stringify!($name),
                repeated_program($body, DEFAULT_SITES),
                $aligned,
                $writable,
                $succeeds,
            );
        }
    };
}

bench_memory!(aligned_load_u8, "ldxb r0, [r1]");
bench_memory!(aligned_load_u16, "ldxh r0, [r1]");
bench_memory!(aligned_load_u32, "ldxw r0, [r1]");
bench_memory!(aligned_load_u64, "ldxdw r0, [r1]");
bench_memory!(aligned_store_u8, "stxb [r1], r4");
bench_memory!(aligned_store_u16, "stxh [r1], r4");
bench_memory!(aligned_store_u32, "stxw [r1], r4");
bench_memory!(aligned_store_u64, "stxdw [r1], r4");
bench_memory!(aligned_immediate_store_u8, "stb [r1], 0x12345678");
bench_memory!(aligned_immediate_store_u16, "sth [r1], 0x12345678");
bench_memory!(aligned_immediate_store_u32, "stw [r1], 0x12345678");
bench_memory!(aligned_immediate_store_u64, "stdw [r1], 0x12345678");
bench_memory!(
    unaligned_mapping_load_u64,
    "ldxdw r0, [r1]",
    false,
    true,
    true
);
bench_memory!(
    unaligned_mapping_store_u64,
    "stxdw [r1], r4",
    false,
    true,
    true
);
bench_memory!(readonly_load_u64, "ldxdw r0, [r1]", true, false, true);
bench_memory!(unaligned_address_load_u64, "ldxdw r0, [r1+1]");
// The second mapped stack frame begins at guest offset 8192, host offset 4096.
bench_memory!(gapped_stack_load_u64, "ldxdw r0, [r5+8192]");
bench_memory!(gapped_stack_store_u64, "stxdw [r5+8192], r4");
bench_memory!(
    mixed_regions,
    "ldxdw r0, [r1]\nldxdw r7, [r2]\nstxdw [r2+8], r4\nldxdw r8, [r5+8192]"
);
bench_memory!(
    mixed_arithmetic,
    "ldxdw r0, [r1]\nadd64 r0, 1\nmul64 r0, 3\nxor64 r0, 0x12345678"
);
bench_memory!(arithmetic_control, "add64 r0, 1\nxor64 r0, 0x12345678");
bench_memory!(readonly_store_fault, "stxdw [r1], r4", true, false, false);
bench_memory!(
    out_of_bounds_load_fault,
    "ldxdw r0, [r1+1020]",
    true,
    true,
    false
);
bench_memory!(
    unmapped_region_load_fault,
    "ldxdw r0, [r6]",
    true,
    true,
    false
);
bench_memory!(
    stack_gap_load_fault,
    "ldxdw r0, [r5+4096]",
    true,
    true,
    false
);

#[bench]
fn code_footprint_64_sites(bencher: &mut Bencher) {
    bench_execution(
        bencher,
        "code_footprint_64_sites",
        repeated_program("ldxdw r0, [r1]", 64),
        true,
        true,
        true,
    );
}

#[bench]
fn code_footprint_1024_sites(bencher: &mut Bencher) {
    bench_execution(
        bencher,
        "code_footprint_1024_sites",
        repeated_program("ldxdw r0, [r1]", 1024),
        true,
        true,
        true,
    );
}

fn bench_capacity(bencher: &mut Bencher, name: &str, instruction_count: usize) {
    let (mut assembly, count) = repeated_program("ldxdw r0, [r1]", DEFAULT_SITES);
    let padding = instruction_count - (DEFAULT_SITES + 6) - 1;
    // Unreachable instructions change the allocation estimate without adding
    // executed work. These sizes fill the 128 KiB pool block on 16/4 KiB pages.
    assembly.push_str(&format!("\n{}exit", "add64 r0, 0\n".repeat(padding)));
    bench_execution(bencher, name, (assembly, count), true, true, true);
}

#[bench]
fn capacity_950_instructions(bencher: &mut Bencher) {
    bench_capacity(bencher, "capacity_950_instructions", 950);
}

#[bench]
fn capacity_1070_instructions(bencher: &mut Bencher) {
    bench_capacity(bencher, "capacity_1070_instructions", 1070);
}

#[bench]
fn sequential_load_u64(bencher: &mut Bencher) {
    let body: String = (0..128)
        .map(|i| format!("ldxdw r0, [r1+{}]\n", i * 8))
        .collect();
    // Use 128 distinct offsets with the same loop count as aligned_load_u64.
    bench_execution(
        bencher,
        "sequential_load_u64",
        loop_program(body.trim_end(), 128),
        true,
        true,
        true,
    );
}

fn bench_compile(bencher: &mut Bencher, name: &str, sites: usize) {
    let executable = executable(&repeated_program("ldxdw r0, [r1]", sites).0, true);
    // Assembly and verification are excluded. jit_compile replaces the prior
    // compiled program on every call, including allocation, emission and sealing.
    bencher.iter(|| executable.jit_compile().unwrap());
    print_code_size(name, &executable);
}

#[bench]
fn compile_128_sites(bencher: &mut Bencher) {
    bench_compile(bencher, "compile_128_sites", 128);
}

#[bench]
fn compile_1024_sites(bencher: &mut Bencher) {
    bench_compile(bencher, "compile_1024_sites", 1024);
}

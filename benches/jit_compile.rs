// Copyright 2020 Solana Maintainers <maintainers@solana.com>
//
// Licensed under the Apache License, Version 2.0 <http://www.apache.org/licenses/LICENSE-2.0> or
// the MIT license <http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

#![feature(test)]
#![cfg(target_arch = "x86_64")]

extern crate solana_sbpf;
extern crate test;

use solana_sbpf::{
    elf::Executable,
    program::{BuiltinProgram, FunctionRegistry, SBPFVersion},
    verifier::RequisiteVerifier,
    vm::Config,
};
use std::{fs::File, io::Read, sync::Arc};
use test::Bencher;
use test_utils::{create_vm, TestContextObject};

#[bench]
fn bench_init_vm(bencher: &mut Bencher) {
    let mut file = File::open("tests/elfs/relative_call_sbpfv0.so").unwrap();
    let mut elf = Vec::new();
    file.read_to_end(&mut elf).unwrap();
    let executable =
        Executable::<TestContextObject>::from_elf(&elf, Arc::new(BuiltinProgram::new_mock()))
            .unwrap();
    executable.verify::<RequisiteVerifier>().unwrap();
    bencher.iter(|| {
        let mut context_object = TestContextObject::default();
        create_vm!(
            _vm,
            &executable,
            &mut context_object,
            stack,
            heap,
            Vec::new(),
            None
        );
    });
}

#[cfg(all(feature = "jit", not(target_os = "windows")))]
#[bench]
fn bench_jit_compile(bencher: &mut Bencher) {
    let mut file = File::open("tests/elfs/relative_call_sbpfv0.so").unwrap();
    let mut elf = Vec::new();
    file.read_to_end(&mut elf).unwrap();
    let executable =
        Executable::<TestContextObject>::from_elf(&elf, Arc::new(BuiltinProgram::new_mock()))
            .unwrap();
    executable.verify::<RequisiteVerifier>().unwrap();
    bencher.iter(|| executable.jit_compile().unwrap());
    bencher.bytes = executable
        .get_compiled_program()
        .unwrap()
        .machine_code_length() as u64;
}

#[cfg(all(feature = "jit", not(target_os = "windows")))]
#[bench]
fn bench_jit_compile_sbpfv3(bencher: &mut Bencher) {
    let mut file = File::open("tests/elfs/relative_call.so").unwrap();
    let mut elf = Vec::new();
    file.read_to_end(&mut elf).unwrap();
    let executable =
        Executable::<TestContextObject>::from_elf(&elf, Arc::new(BuiltinProgram::new_mock()))
            .unwrap();
    executable.verify::<RequisiteVerifier>().unwrap();
    bencher.iter(|| executable.jit_compile().unwrap());
    bencher.bytes = executable
        .get_compiled_program()
        .unwrap()
        .machine_code_length() as u64;
}

/// The text section of an SBPFv3 program, repeated `repeat` times.
fn sbpfv3_text(repeat: usize) -> Vec<u8> {
    let mut file = File::open("tests/elfs/relative_call.so").unwrap();
    let mut elf = Vec::new();
    file.read_to_end(&mut elf).unwrap();
    let executable =
        Executable::<TestContextObject>::from_elf(&elf, Arc::new(BuiltinProgram::new_mock()))
            .unwrap();
    executable.verify::<RequisiteVerifier>().unwrap();
    // All the branches and calls are relative, so the copies are valid code too.
    executable.get_text_bytes().1.repeat(repeat)
}

/// 10 MiB of BPF code consisting of `insn` alone.
fn filled_text(insn: [u8; 8]) -> Vec<u8> {
    insn.repeat(10 << 20 >> 3)
}

/// No machine code at all: `mov64 r1, r1`.
const EMPTY_INSN: [u8; 8] = [0xbf, 0x11, 0, 0, 0, 0, 0, 0];
/// The least machine code with a relocation: `mov32 r1, 1`.
const SMALLEST_INSN: [u8; 8] = [0xb4, 0x01, 0, 0, 1, 0, 0, 0];
/// The most machine code, with three kinds of relocations: `jsle64 r1, 1, -1`.
const LARGEST_INSN: [u8; 8] = [0xd5, 0x01, 0xff, 0xff, 1, 0, 0, 0];

fn bench_dynasm_jit_compile_impl(bencher: &mut Bencher, text: Vec<u8>) {
    let templates = solana_sbpf::codegen::x64::jit_templates(SBPFVersion::V3);
    let executable = sbpfv3_executable(&text);
    // Exclude the template generation.
    bencher.bytes = templates.compile(&executable).text_section.len() as u64;
    bencher.iter(|| templates.compile(&executable));
}

#[bench]
fn bench_dynasm_jit_compile(bencher: &mut Bencher) {
    bench_dynasm_jit_compile_impl(bencher, sbpfv3_text(1));
}

#[bench]
fn bench_dynasm_jit_compile_large(bencher: &mut Bencher) {
    bench_dynasm_jit_compile_impl(bencher, sbpfv3_text(4096));
}

#[bench]
fn bench_dynasm_jit_compile_10mib_empty(bencher: &mut Bencher) {
    bench_dynasm_jit_compile_impl(bencher, filled_text(EMPTY_INSN));
}

#[bench]
fn bench_dynasm_jit_compile_10mib_smallest(bencher: &mut Bencher) {
    bench_dynasm_jit_compile_impl(bencher, filled_text(SMALLEST_INSN));
}

#[bench]
fn bench_dynasm_jit_compile_10mib_largest(bencher: &mut Bencher) {
    bench_dynasm_jit_compile_impl(bencher, filled_text(LARGEST_INSN));
}

#[bench]
fn bench_dynasm_jit_compile_10mib_random(bencher: &mut Bencher) {
    use rand::{rngs::SmallRng, Rng, SeedableRng};
    let mut rng = SmallRng::seed_from_u64(0);
    let text = (0..10 << 20 >> 3)
        .flat_map(|_| {
            let (low, imm) = (rng.gen::<u16>(), rng.gen::<u32>());
            (u64::from(low) | u64::from(imm) << 32).to_le_bytes()
        })
        .collect();
    bench_dynasm_jit_compile_impl(bencher, text);
}

/// An unverified SBPFv3 executable of `text`, compiled without no-ops.
fn sbpfv3_executable(text: &[u8]) -> Executable<TestContextObject> {
    let config = Config {
        noop_instruction_rate: 0,
        ..Config::default()
    };
    Executable::<TestContextObject>::from_text_bytes(
        text,
        Arc::new(BuiltinProgram::new_loader(config)),
        SBPFVersion::V3,
        FunctionRegistry::default(),
    )
    .unwrap()
}

#[cfg(all(feature = "jit", not(target_os = "windows")))]
fn bench_jit_compile_impl(bencher: &mut Bencher, text: Vec<u8>) {
    let executable = sbpfv3_executable(&text);
    bencher.iter(|| executable.jit_compile().unwrap());
    bencher.bytes = executable
        .get_compiled_program()
        .unwrap()
        .machine_code_length() as u64;
}

#[cfg(all(feature = "jit", not(target_os = "windows")))]
#[bench]
fn bench_jit_compile_10mib_empty(bencher: &mut Bencher) {
    bench_jit_compile_impl(bencher, filled_text(EMPTY_INSN));
}

#[cfg(all(feature = "jit", not(target_os = "windows")))]
#[bench]
fn bench_jit_compile_10mib_smallest(bencher: &mut Bencher) {
    bench_jit_compile_impl(bencher, filled_text(SMALLEST_INSN));
}

#[cfg(all(feature = "jit", not(target_os = "windows")))]
#[bench]
fn bench_jit_compile_10mib_largest(bencher: &mut Bencher) {
    bench_jit_compile_impl(bencher, filled_text(LARGEST_INSN));
}

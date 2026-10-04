// Copyright 2020 Solana Maintainers <maintainers@solana.com>
//
// Licensed under the Apache License, Version 2.0 <http://www.apache.org/licenses/LICENSE-2.0> or
// the MIT license <http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

extern crate solana_sbpf;

#[cfg(target_arch = "x86_64")]
mod x86_64 {
    use criterion::{criterion_group, Criterion, Throughput};
    use solana_sbpf::{
        elf::Executable,
        program::{BuiltinProgram, FunctionRegistry, SBPFVersion},
        verifier::RequisiteVerifier,
        vm::Config,
    };
    use std::{fs::File, io::Read, sync::Arc};
    use test_utils::{create_vm, TestContextObject};

    fn bench_init_vm(c: &mut Criterion) {
        let mut file = File::open("tests/elfs/relative_call_sbpfv0.so").unwrap();
        let mut elf = Vec::new();
        file.read_to_end(&mut elf).unwrap();
        let executable =
            Executable::<TestContextObject>::from_elf(&elf, Arc::new(BuiltinProgram::new_mock()))
                .unwrap();
        executable.verify::<RequisiteVerifier>().unwrap();
        c.bench_function("bench_init_vm", |b| {
            b.iter(|| {
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
            })
        });
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

    fn elf_executable(path: &str) -> Executable<TestContextObject> {
        let mut file = File::open(path).unwrap();
        let mut elf = Vec::new();
        file.read_to_end(&mut elf).unwrap();
        let executable =
            Executable::<TestContextObject>::from_elf(&elf, Arc::new(BuiltinProgram::new_mock()))
                .unwrap();
        executable.verify::<RequisiteVerifier>().unwrap();
        executable
    }

    fn bench_compile(
        c: &mut Criterion,
        name: &str,
        executable: &Executable<TestContextObject>,
        jit_supported: bool,
    ) {
        let templates = solana_sbpf::codegen::x64::jit_templates(executable.get_sbpf_version());
        let mut group = c.benchmark_group(format!("compile/{name}"));
        group.throughput(Throughput::Bytes(executable.get_text_bytes().1.len() as u64));
        #[cfg(all(feature = "jit", not(target_os = "windows")))]
        if jit_supported {
            group.bench_function("jit", |b| b.iter(|| executable.jit_compile().unwrap()));
        }
        #[cfg(not(all(feature = "jit", not(target_os = "windows"))))]
        let _ = jit_supported;
        group.bench_function("dynasm", |b| {
            b.iter(|| templates.compile(executable).unwrap())
        });
        group.finish();
    }

    fn bench_compile_relative_call_sbpfv0(c: &mut Criterion) {
        bench_compile(
            c,
            "relative_call_sbpfv0",
            &elf_executable("tests/elfs/relative_call_sbpfv0.so"),
            true,
        );
    }

    fn bench_compile_relative_call_sbpfv3(c: &mut Criterion) {
        bench_compile(
            c,
            "relative_call_sbpfv3",
            &elf_executable("tests/elfs/relative_call.so"),
            true,
        );
    }

    fn bench_compile_large(c: &mut Criterion) {
        bench_compile(c, "large", &sbpfv3_executable(&sbpfv3_text(4096)), true);
    }

    fn bench_compile_10mib_empty(c: &mut Criterion) {
        bench_compile(
            c,
            "10mib_empty",
            &sbpfv3_executable(&filled_text(EMPTY_INSN)),
            true,
        );
    }

    fn bench_compile_10mib_smallest(c: &mut Criterion) {
        bench_compile(
            c,
            "10mib_smallest",
            &sbpfv3_executable(&filled_text(SMALLEST_INSN)),
            true,
        );
    }

    fn bench_compile_10mib_largest(c: &mut Criterion) {
        bench_compile(
            c,
            "10mib_largest",
            &sbpfv3_executable(&filled_text(LARGEST_INSN)),
            true,
        );
    }

    fn bench_compile_10mib_random(c: &mut Criterion) {
        use rand::{rngs::SmallRng, Rng, SeedableRng};
        let mut rng = SmallRng::seed_from_u64(0);
        let text: Vec<u8> = (0..10 << 20 >> 3)
            .flat_map(|_| {
                let (low, imm) = (rng.gen::<u16>(), rng.gen::<u32>());
                (u64::from(low) | u64::from(imm) << 32).to_le_bytes()
            })
            .collect();
        // The old JIT panics on instructions that would not pass verification.
        bench_compile(c, "10mib_random", &sbpfv3_executable(&text), false);
    }

    criterion_group!(
        benches,
        bench_init_vm,
        bench_compile_relative_call_sbpfv0,
        bench_compile_relative_call_sbpfv3,
        bench_compile_large,
        bench_compile_10mib_empty,
        bench_compile_10mib_smallest,
        bench_compile_10mib_largest,
        bench_compile_10mib_random,
    );
}

#[cfg(target_arch = "x86_64")]
criterion::criterion_main!(x86_64::benches);

#[cfg(not(target_arch = "x86_64"))]
fn main() {}

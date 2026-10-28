// Copyright 2020 Solana Maintainers <maintainers@solana.com>
//
// Licensed under the Apache License, Version 2.0 <http://www.apache.org/licenses/LICENSE-2.0> or
// the MIT license <http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

extern crate solana_sbpf;
extern crate test_utils;

use criterion::{criterion_group, criterion_main, BenchmarkGroup, BenchmarkId, Criterion};
use criterion::{measurement::WallTime, Throughput};
use solana_sbpf::{
    elf::Executable,
    program::{BuiltinFunctionDefinition, BuiltinProgram, SBPFVersion},
    verifier::RequisiteVerifier,
    vm::Config,
};
use std::{fs, sync::Arc};
use test_utils::{syscalls, TestContextObject};

/// The programs in `tests/elfs` that are built for both SBPFv0, as `{name}_sbpfv0.so`, and SBPFv3,
/// as `{name}.so`.
const ELFS: [&str; 11] = [
    "large_rodata",
    "long_symbol_name",
    "many_functions",
    "many_relocations",
    "relative_call",
    "reloc_64_64",
    "reloc_64_relative",
    "reloc_64_relative_data",
    "rodata_section",
    "straight_line",
    "struct_func_pointer",
];

fn loader() -> Arc<BuiltinProgram<TestContextObject>> {
    let mut loader = BuiltinProgram::new_loader(Config::default());
    syscalls::SyscallString::register(&mut loader, "log").unwrap();
    Arc::new(loader)
}

/// Verify `elf`, which is built for `version`, by ELF size, so that it adds to loading.
fn bench_verify(
    group: &mut BenchmarkGroup<WallTime>,
    loader: &Arc<BuiltinProgram<TestContextObject>>,
    name: &str,
    version: SBPFVersion,
    elf: &[u8],
) {
    let executable = Executable::<TestContextObject>::from_elf(elf, loader.clone()).unwrap();
    assert_eq!(executable.get_sbpf_version(), version);
    group.throughput(Throughput::Bytes(elf.len() as u64));
    let id = BenchmarkId::new(name, format!("{version:?}").to_lowercase());
    group.bench_function(id, |b| {
        b.iter(|| executable.verify::<RequisiteVerifier>().unwrap())
    });
}

/// The programs of the `elf_loader` bench, with the verifier the runtime deploys with.
fn bench_verify_elfs(c: &mut Criterion) {
    let loader = loader();
    let mut group = c.benchmark_group("verify");
    for name in ELFS {
        for (version, file) in [
            (SBPFVersion::V0, format!("{name}_sbpfv0.so")),
            (SBPFVersion::V3, format!("{name}.so")),
        ] {
            let elf = fs::read(format!("tests/elfs/{file}")).unwrap();
            bench_verify(&mut group, &loader, name, version, &elf);
        }
    }
    group.finish();
}

criterion_group!(benches, bench_verify_elfs);
criterion_main!(benches);

// Copyright 2020 Solana Maintainers <maintainers@solana.com>
//
// Licensed under the Apache License, Version 2.0 <http://www.apache.org/licenses/LICENSE-2.0> or
// the MIT license <http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

extern crate solana_sbpf;

use criterion::{criterion_group, criterion_main, BenchmarkGroup, BenchmarkId, Criterion};
use criterion::{measurement::WallTime, Throughput};
use solana_sbpf::{
    elf::{get_sbpf_version, Executable},
    program::{BuiltinFunctionDefinition, BuiltinProgram, SBPFVersion},
    test_syscalls,
    test_utils::TestContextObject,
    vm::Config,
};
use std::{fs, sync::Arc};

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
    test_syscalls::SyscallString::register(&mut loader, "log").unwrap();
    Arc::new(loader)
}

/// Load `elf`, which is built for `version`, by ELF size.
fn bench_load(
    group: &mut BenchmarkGroup<WallTime>,
    loader: &Arc<BuiltinProgram<TestContextObject>>,
    name: &str,
    version: SBPFVersion,
    elf: &[u8],
) {
    assert_eq!(get_sbpf_version(elf).unwrap(), version);
    group.throughput(Throughput::Bytes(elf.len() as u64));
    let id = BenchmarkId::new(name, format!("{version:?}").to_lowercase());
    group.bench_function(id, |b| {
        b.iter(|| Executable::<TestContextObject>::from_elf(elf, loader.clone()).unwrap())
    });
}

/// The same programs on both loading paths: SBPFv0 is parsed leniently and relocated, and SBPFv3
/// is parsed strictly, without relocations.
fn bench_load_elfs(c: &mut Criterion) {
    let loader = loader();
    let mut group = c.benchmark_group("load");
    for name in ELFS {
        for (version, file) in [
            (SBPFVersion::V0, format!("{name}_sbpfv0.so")),
            (SBPFVersion::V3, format!("{name}.so")),
        ] {
            let elf = fs::read(format!("tests/elfs/{file}")).unwrap();
            bench_load(&mut group, &loader, name, version, &elf);
        }
    }
    group.finish();
}

criterion_group!(benches, bench_load_elfs);
criterion_main!(benches);

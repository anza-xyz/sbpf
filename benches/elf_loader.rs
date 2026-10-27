// Copyright 2020 Solana Maintainers <maintainers@solana.com>
//
// Licensed under the Apache License, Version 2.0 <http://www.apache.org/licenses/LICENSE-2.0> or
// the MIT license <http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

extern crate solana_sbpf;
extern crate test_utils;

use criterion::{criterion_group, criterion_main, Criterion};
use solana_sbpf::{
    elf::Executable,
    program::{BuiltinFunctionDefinition, BuiltinProgram},
    vm::Config,
};
use std::{fs::File, io::Read, sync::Arc};
use test_utils::{syscalls, TestContextObject};

fn loader() -> Arc<BuiltinProgram<TestContextObject>> {
    let mut loader = BuiltinProgram::new_loader(Config::default());
    syscalls::SyscallString::register(&mut loader, "log").unwrap();
    Arc::new(loader)
}

fn bench_load_sbpfv0(c: &mut Criterion) {
    let mut file = File::open("tests/elfs/syscall_reloc_64_32_sbpfv0.so").unwrap();
    let mut elf = Vec::new();
    file.read_to_end(&mut elf).unwrap();
    let loader = loader();
    c.bench_function("bench_load_sbpfv0", |b| {
        b.iter(|| Executable::<TestContextObject>::from_elf(&elf, loader.clone()).unwrap())
    });
}

criterion_group!(benches, bench_load_sbpfv0);
criterion_main!(benches);

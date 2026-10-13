extern crate rand;
extern crate solana_sbpf;
extern crate test_utils;

use criterion::{criterion_group, criterion_main, BenchmarkGroup, BenchmarkId, Criterion};
use criterion::{measurement::WallTime, Throughput};
use rand::{rngs::SmallRng, Rng, SeedableRng};
use solana_sbpf::{ebpf, program::BuiltinProgram};
use std::hint::black_box;
use test_utils::{syscalls::SyscallMemFrob, TestContextObject};

const LOOKUPS: usize = 1 << 16;

/// `LOOKUPS` random keys of the `len` names `{prefix}{i}`, or of other names with `misses`.
fn lookups(prefix: &str, len: usize, misses: bool) -> Vec<u32> {
    let mut prng = SmallRng::seed_from_u64(0);
    (0..LOOKUPS)
        .map(|_| {
            let name = if misses {
                format!("{prefix}missing_{}", prng.gen::<u64>())
            } else {
                format!("{prefix}{}", prng.gen_range(0..len))
            };
            ebpf::hash_symbol_name(name.as_bytes())
        })
        .collect()
}

/// Look up the `keys` with `lookup`, which returns a number of what it finds: independently, which
/// the CPU can overlap, and with each key depending on the previous result, as a dispatch waits on
/// the lookup.
fn bench_lookups(
    group: &mut BenchmarkGroup<WallTime>,
    name: &str,
    len: usize,
    keys: &[u32],
    lookup: impl Fn(u32) -> Option<u32>,
) {
    group.bench_function(BenchmarkId::new(format!("{name}_throughput"), len), |b| {
        b.iter(|| {
            for &key in keys {
                black_box(lookup(black_box(key)));
            }
        })
    });
    group.bench_function(BenchmarkId::new(format!("{name}_latency"), len), |b| {
        let zero = black_box(0);
        b.iter(|| {
            let mut carry = 0;
            for &key in keys {
                carry = lookup(key ^ (carry & zero)).unwrap_or(1);
            }
            carry
        })
    });
}

/// The syscalls of a loader.
fn bench_syscalls(c: &mut Criterion) {
    let mut group = c.benchmark_group("syscalls");
    group.throughput(Throughput::Elements(LOOKUPS as u64));
    for len in [64, 256] {
        let mut loader = BuiltinProgram::<TestContextObject>::new_mock();
        for i in 0..len {
            loader
                .register_definition::<SyscallMemFrob>(&format!("syscall_{i}"))
                .unwrap();
        }
        let registry = loader.syscall_registry();
        let lookup = |key| {
            registry
                .lookup_by_key(key)
                .map(|(_, (function, _))| function as usize as u32)
        };
        for (name, misses) in [("hit", false), ("miss", true)] {
            let keys = lookups("syscall_", len, misses);
            bench_lookups(&mut group, name, len, &keys, lookup);
        }
    }
    group.finish();
}

criterion_group!(benches, bench_syscalls);
criterion_main!(benches);

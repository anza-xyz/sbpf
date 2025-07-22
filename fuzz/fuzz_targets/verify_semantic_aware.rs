#![no_main]

use libfuzzer_sys::fuzz_target;

use semantic_aware::*;
use solana_sbpf::{
    insn_builder::IntoBytes,
    program::{BuiltinFunction, FunctionRegistry, SBPFVersion},
    verifier::{RequisiteVerifier, Verifier},
};
use test_utils::TestContextObject;

use crate::common::ConfigTemplate;

mod common;
mod semantic_aware;

#[derive(arbitrary::Arbitrary, Debug)]
struct FuzzData {
    template: ConfigTemplate,
    prog: FuzzProgram,
}

fuzz_target!(|data: FuzzData| {
    let prog = make_program(&data.prog);
    let sbpf_version = data.template.sbpf_version;
    let config = data.template.into();
    let function_registry = FunctionRegistry::default();
    let syscall_registry = FunctionRegistry::<BuiltinFunction<TestContextObject>>::default();

    RequisiteVerifier::verify(
        prog.into_bytes(),
        &config,
        sbpf_version,
        &function_registry,
        &syscall_registry,
    )
    .unwrap();
});

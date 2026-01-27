#![no_main]

use {
    crate::common::ConfigTemplate,
    libfuzzer_sys::fuzz_target,
    semantic_aware::*,
    solana_sbpf::{
        insn_builder::IntoBytes,
        program::{BuiltinFunction, FunctionRegistry},
        verifier::{RequisiteVerifier, Verifier},
    },
    test_utils::TestContextObject,
};

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

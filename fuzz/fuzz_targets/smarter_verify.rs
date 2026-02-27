#![no_main]

use libfuzzer_sys::fuzz_target;

use semantic_aware::*;
use solana_sbpf::{
    insn_builder::IntoBytes,
    verifier::{RequisiteVerifier, Verifier},
};

use crate::common::ConfigTemplate;

mod common;
mod semantic_aware;

#[derive(arbitrary::Arbitrary, Debug)]
struct FuzzData {
    template: ConfigTemplate,
    prog: FuzzProgram,
}

fuzz_target!(|data: FuzzData| {
    let sbpf_version = data.template.sbpf_version;
    let prog = make_program(&data.prog, sbpf_version);
    let config = data.template.into();

    #[allow(unused)]
    let res = RequisiteVerifier::verify(prog.into_bytes(), &config, sbpf_version);
    #[cfg(feature = "only-verified")]
    assert!(res.is_ok(), "Verification failed: {:?}", res.err());
});

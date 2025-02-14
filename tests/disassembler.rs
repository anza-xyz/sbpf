#![allow(clippy::literal_string_with_formatting_args)]

// Copyright 2017 Jan-Erik Rediger <badboy@archlinux.us>
//
// Adopted from tests in `tests/assembler.rs`
//
// Licensed under the Apache License, Version 2.0 <http://www.apache.org/licenses/LICENSE-2.0> or
// the MIT license <http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

extern crate solana_sbpf;
use solana_sbpf::program::SBPFVersion;
use solana_sbpf::{
    assembler::assemble, program::BuiltinProgram, static_analysis::Analysis, vm::Config,
};
use std::sync::Arc;
use test_utils::TestContextObject;

// Using a macro to keep actual line numbers in failure output
macro_rules! disasm {
    ($src:expr) => {{
        let config = Config {
            enable_symbol_and_section_labels: true,
            ..Config::default()
        };
        disasm!($src, config);
    }};
    ($src:expr, $config:expr) => {{
        let src = $src;
        let loader = BuiltinProgram::new_loader($config);
        let executable = assemble::<TestContextObject>(src, Arc::new(loader)).unwrap();
        let analysis = Analysis::from_executable(&executable).unwrap();
        let mut reasm = Vec::new();
        analysis.disassemble(&mut reasm).unwrap();
        assert_eq!(src, String::from_utf8(reasm).unwrap());
    }};
}

#[test]
fn test_empty() {
    disasm!("");
}

// Example for InstructionType::NoOperand.
#[test]
fn test_exit() {
    let config = Config {
        enabled_sbpf_versions: SBPFVersion::V0..=SBPFVersion::V0,
        ..Config::default()
    };
    disasm!("entrypoint:\n    exit\n", config);
}

#[test]
fn test_return() {
    let config = Config {
        enabled_sbpf_versions: SBPFVersion::V3..=SBPFVersion::V3,
        ..Config::default()
    };
    disasm!("entrypoint:\n    return\n", config);
}

#[test]
fn test_static_syscall() {
    let config = Config {
        enabled_sbpf_versions: SBPFVersion::V3..=SBPFVersion::V3,
        ..Config::default()
    };
    disasm!("entrypoint:\n    syscall 5\n", config);
}

// Example for InstructionType::AluBinary.
#[test]
fn test_add64() {
    disasm!("entrypoint:\n    add64 r1, r3\n");
    disasm!("entrypoint:\n    add64 r1, 5\n");
}

// Example for InstructionType::LoadReg.
#[test]
fn test_ldxw() {
    disasm!("entrypoint:\n    ldxw r1, [r2+0x5]\n");
    disasm!("entrypoint:\n    ldxw r1, [r2-0x5]\n");
}

// Example for InstructionType::StoreImm.
#[test]
fn test_stw() {
    disasm!("entrypoint:\n    stw [r2+0x5], 7\n");
    disasm!("entrypoint:\n    stw [r2-0x5], 7\n");
}

// Example for InstructionType::StoreReg.
#[test]
fn test_stxw() {
    disasm!("entrypoint:\n    stxw [r2+0x5], r8\n");
    disasm!("entrypoint:\n    stxw [r2-0x5], r8\n");
}

// Example for InstructionType::JumpUnconditional.
#[test]
fn test_ja() {
    disasm!(
        "entrypoint:
    ja lbb_1
lbb_1:
    return
"
    );
}

// Example for InstructionType::JumpConditional.
#[test]
fn test_jeq() {
    disasm!(
        "entrypoint:
    jeq r1, 4, lbb_1
lbb_1:
    return
"
    );
    disasm!(
        "entrypoint:
    jeq r1, r3, lbb_1
lbb_1:
    return
"
    );
}

// Example for InstructionType::Call.
#[test]
fn test_call() {
    disasm!(
        "entrypoint:
    call function_1

function_1:
    return
"
    );
}

// Example for InstructionType::Endian.
#[test]
fn test_be32() {
    disasm!("entrypoint:\n    be32 r1\n");
}

// Example for InstructionType::LoadImm.
#[test]
fn test_lddw() {
    disasm!("entrypoint:\n    lddw r1, 0x1234abcd5678eeff\n");
    disasm!("entrypoint:\n    lddw r1, 0xff11ee22dd33cc44\n");
}

// Example for InstructionType::LoadReg.
#[test]
fn test_ldxdw() {
    disasm!("entrypoint:\n    ldxdw r1, [r2+0x7999]\n");
    disasm!("entrypoint:\n    ldxdw r1, [r2-0x8000]\n");
}

// Example for InstructionType::StoreImm.
#[test]
fn test_sth() {
    disasm!("entrypoint:\n    sth [r1+0x7999], 3\n");
    disasm!("entrypoint:\n    sth [r1-0x8000], 3\n");
}

// Example for InstructionType::StoreReg.
#[test]
fn test_stxh() {
    disasm!("entrypoint:\n    stxh [r1+0x7999], r3\n");
    disasm!("entrypoint:\n    stxh [r1-0x8000], r3\n");
}

// Test all supported AluBinary mnemonics.
#[test]
fn test_alu_binary() {
    disasm!(
        "entrypoint:
    add64 r1, r2
    sub64 r1, r2
    or64 r1, r2
    and64 r1, r2
    lsh64 r1, r2
    rsh64 r1, r2
    xor64 r1, r2
    mov64 r1, r2
    arsh64 r1, r2
"
    );

    disasm!(
        "entrypoint:
    add64 r1, 2
    sub64 r1, 2
    or64 r1, 2
    and64 r1, 2
    lsh64 r1, 2
    rsh64 r1, 2
    xor64 r1, 2
    mov64 r1, 2
    arsh64 r1, 2
"
    );

    disasm!(
        "entrypoint:
    add32 r1, r2
    sub32 r1, r2
    or32 r1, r2
    and32 r1, r2
    lsh32 r1, r2
    rsh32 r1, r2
    xor32 r1, r2
    mov32 r1, r2
    arsh32 r1, r2
"
    );

    disasm!(
        "entrypoint:
    add32 r1, 2
    sub32 r1, 2
    or32 r1, 2
    and32 r1, 2
    lsh32 r1, 2
    rsh32 r1, 2
    xor32 r1, 2
    mov32 r1, 2
    arsh32 r1, 2
"
    );

    disasm!(
        "entrypoint:
    lmul64 r1, r2
    lmul32 r1, r2
    uhmul64 r1, r2
    shmul64 r1, r2
    udiv64 r1, r2
    udiv32 r1, r2
    urem64 r1, r2
    urem32 r1, r2
    sdiv64 r1, r2
    sdiv32 r1, r2
    srem64 r1, r2
    srem32 r1, r2
"
    );

    disasm!(
        "entrypoint:
    lmul64 r1, 2
    lmul32 r1, 2
    uhmul64 r1, 2
    shmul64 r1, 2
    udiv64 r1, 2
    udiv32 r1, 2
    urem64 r1, 2
    urem32 r1, 2
    sdiv64 r1, 2
    sdiv32 r1, 2
    srem64 r1, 2
    srem32 r1, 2
"
    );
}

// Test all supported LoadReg mnemonics.
#[test]
fn test_load_reg() {
    disasm!(
        r"entrypoint:
    ldxw r1, [r2+0x3]
    ldxh r1, [r2+0x3]
    ldxb r1, [r2+0x3]
    ldxdw r1, [r2+0x3]
"
    );
}

// Test all supported StoreImm mnemonics.
#[test]
fn test_store_imm() {
    disasm!(
        "entrypoint:
    stw [r1+0x2], 3
    sth [r1+0x2], 3
    stb [r1+0x2], 3
    stdw [r1+0x2], 3
"
    );
}

// Test all supported StoreReg mnemonics.
#[test]
fn test_store_reg() {
    disasm!(
        "entrypoint:
    stxw [r1+0x2], r3
    stxh [r1+0x2], r3
    stxb [r1+0x2], r3
    stxdw [r1+0x2], r3
"
    );
}

// Test all supported JumpConditional mnemonics.
#[test]
fn test_jump_conditional() {
    disasm!(
        "entrypoint:
    jeq r1, r2, lbb_11
    jgt r1, r2, lbb_11
    jge r1, r2, lbb_11
    jlt r1, r2, lbb_11
    jle r1, r2, lbb_11
    jset r1, r2, lbb_11
    jne r1, r2, lbb_11
    jsgt r1, r2, lbb_11
    jsge r1, r2, lbb_11
    jslt r1, r2, lbb_11
    jsle r1, r2, lbb_11
lbb_11:
    return
"
    );

    disasm!(
        "entrypoint:
    jeq r1, 2, lbb_11
    jgt r1, 2, lbb_11
    jge r1, 2, lbb_11
    jlt r1, 2, lbb_11
    jle r1, 2, lbb_11
    jset r1, 2, lbb_11
    jne r1, 2, lbb_11
    jsgt r1, 2, lbb_11
    jsge r1, 2, lbb_11
    jslt r1, 2, lbb_11
    jsle r1, 2, lbb_11
lbb_11:
    return
"
    );
}

// Test all supported Endian mnemonics.
#[test]
fn test_endian() {
    disasm!(
        "entrypoint:
    be16 r1
    be32 r1
    be64 r1
    le16 r1
    le32 r1
    le64 r1
"
    );
}

#[test]
fn test_large_immediate() {
    disasm!("entrypoint:\n    add64 r1, -1\n");
    disasm!("entrypoint:\n    add64 r1, -1\n");
}

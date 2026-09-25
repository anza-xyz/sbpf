use solana_sbpf::{ebpf, elf::Executable, program::SBPFVersion, static_analysis::Analysis};
use solana_sbpf::{
    program::{BuiltinProgram, FunctionRegistry},
    static_analysis::{DataResource, DfgEdgeKind, DfgNode},
};
use std::sync::Arc;
use test_utils::TestContextObject as Context;

fn insn(opc: u8, dst: u8, src: u8, off: i16, imm: i32) -> [u8; 8] {
    let mut bytes = [opc, dst | src << 4, 0, 0, 0, 0, 0, 0];
    bytes[2..4].copy_from_slice(&off.to_le_bytes());
    bytes[4..8].copy_from_slice(&imm.to_le_bytes());
    bytes
}

fn executable(code: &[[u8; 8]], version: SBPFVersion) -> Executable<Context> {
    Executable::from_text_bytes(
        &code.concat(),
        Arc::new(BuiltinProgram::new_mock()),
        version,
        FunctionRegistry::default(),
    )
    .unwrap()
}

fn entry_read(analysis: &Analysis<'_>, pc: usize, reg: u8) -> bool {
    analysis
        .dfg_reverse_edges
        .get(&DfgNode::InstructionNode(pc))
        .is_some_and(|edges| {
            edges.iter().any(|edge| {
                edge.source == DfgNode::PhiNode(analysis.entrypoint)
                    && edge.resource == DataResource::Register(reg)
                    && edge.kind == DfgEdgeKind::Filled
            })
        })
}

#[test]
fn callx_reads_the_version_specific_target_register() {
    for (version, field) in [
        (SBPFVersion::V0, 0),
        (SBPFVersion::V1, 0),
        (SBPFVersion::V2, 1),
        (SBPFVersion::V3, 2),
        (SBPFVersion::V4, 2),
    ] {
        for target in 6..10 {
            for initialized in [false, true] {
                let mut fields = [6, 7, 8]; // imm, src, dst
                fields[field] = target;
                let mut code = Vec::new();
                if initialized {
                    code.push(insn(ebpf::MOV64_IMM, target, 0, 0, 0));
                }
                let call_pc = code.len();
                code.push(insn(
                    ebpf::CALL_REG,
                    fields[2],
                    fields[1],
                    0,
                    fields[0] as i32,
                ));
                code.push(insn(ebpf::EXIT, 0, 0, 0, 0));
                let exe = executable(&code, version);
                let analysis = Analysis::from_executable(&exe).unwrap();
                let edges = &analysis.dfg_reverse_edges[&DfgNode::InstructionNode(call_pc)];
                for reg in 6..10 {
                    let reads = edges.iter().any(|edge| {
                        edge.resource == DataResource::Register(reg)
                            && edge.kind == DfgEdgeKind::Filled
                    });
                    assert_eq!(
                        reads,
                        reg == target,
                        "{version:?}, target r{target}, read r{reg}"
                    );
                }
                let source = if initialized {
                    DfgNode::InstructionNode(0)
                } else {
                    DfgNode::PhiNode(analysis.entrypoint)
                };
                assert!(edges.iter().any(|edge| {
                    edge.source == source
                        && edge.resource == DataResource::Register(target)
                        && edge.kind == DfgEdgeKind::Filled
                }));
            }
        }
    }
}

#[test]
fn v2_loads_overwrite_destination_but_read_address() {
    for opcode in [
        ebpf::LD_1B_REG,
        ebpf::LD_2B_REG,
        ebpf::LD_4B_REG,
        ebpf::LD_8B_REG,
    ] {
        let exe = executable(
            &[
                insn(opcode, 2, 1, 0, 0),
                insn(ebpf::MOV64_REG, 0, 2, 0, 0),
                insn(ebpf::EXIT, 0, 0, 0, 0),
            ],
            SBPFVersion::V2,
        );
        let fixed = Analysis::from_executable(&exe).unwrap();
        assert!(!entry_read(&fixed, 0, 2));
        assert!(!entry_read(&fixed, 1, 2));
        assert!(entry_read(&fixed, 0, 1));
        assert_eq!(fixed.instructions[0].opc, opcode);
        assert!(fixed
            .disassemble_instruction(&fixed.instructions[0], 0)
            .starts_with("ldx"));
    }
}

#[test]
fn legacy_modulo_is_still_a_real_read() {
    for version in [
        SBPFVersion::V0,
        SBPFVersion::V1,
        SBPFVersion::V3,
        SBPFVersion::V4,
    ] {
        let exe = executable(
            &[
                insn(ebpf::MOD32_REG, 2, 1, 0, 0),
                insn(ebpf::EXIT, 0, 0, 0, 0),
            ],
            version,
        );
        let fixed = Analysis::from_executable(&exe).unwrap();
        assert!(entry_read(&fixed, 0, 1));
        assert!(entry_read(&fixed, 0, 2));
    }
}

#[test]
fn v2_load_using_its_own_destination_still_reads_it() {
    let exe = executable(
        &[
            insn(ebpf::LD_8B_REG, 2, 2, 0, 0),
            insn(ebpf::EXIT, 0, 0, 0, 0),
        ],
        SBPFVersion::V2,
    );
    assert!(entry_read(&Analysis::from_executable(&exe).unwrap(), 0, 2));
}

#[test]
fn v2_stores_do_not_initialize_the_address_register() {
    for opcode in [
        ebpf::ST_1B_IMM,
        ebpf::ST_2B_IMM,
        ebpf::ST_4B_IMM,
        ebpf::ST_8B_IMM,
        ebpf::ST_1B_REG,
        ebpf::ST_2B_REG,
        ebpf::ST_4B_REG,
        ebpf::ST_8B_REG,
    ] {
        let exe = executable(
            &[
                insn(opcode, 2, 3, 0, 0),
                insn(ebpf::MOV64_REG, 0, 2, 0, 0),
                insn(ebpf::EXIT, 0, 0, 0, 0),
            ],
            SBPFVersion::V2,
        );
        let fixed = Analysis::from_executable(&exe).unwrap();
        assert!(entry_read(&fixed, 0, 2));
        assert!(entry_read(&fixed, 1, 2));
        assert_eq!(entry_read(&fixed, 0, 3), opcode & 8 != 0);
    }
}

#[test]
fn v2_pqr_arithmetic_keeps_real_reads() {
    for opcode in [
        ebpf::LMUL32_REG,
        ebpf::LMUL64_REG,
        ebpf::UHMUL64_REG,
        ebpf::SHMUL64_REG,
        ebpf::UDIV32_REG,
        ebpf::UDIV64_REG,
        ebpf::SDIV32_REG,
        ebpf::SDIV64_REG,
        ebpf::UREM32_REG,
        ebpf::UREM64_REG,
        ebpf::SREM32_REG,
        ebpf::SREM64_REG,
    ] {
        for opcode in [opcode, opcode & !8] {
            let exe = executable(
                &[
                    insn(opcode, 2, 3, 0, 1),
                    insn(ebpf::MOV64_REG, 0, 2, 0, 0),
                    insn(ebpf::EXIT, 0, 0, 0, 0),
                ],
                SBPFVersion::V2,
            );
            let fixed = Analysis::from_executable(&exe).unwrap();
            assert!(entry_read(&fixed, 0, 2));
            assert_eq!(entry_read(&fixed, 0, 3), opcode & 8 != 0);
            assert!(!entry_read(&fixed, 1, 2));
        }
    }
}

#[test]
fn load_definition_reaches_a_successor_block() {
    let exe = executable(
        &[
            insn(ebpf::LD_8B_REG, 2, 1, 0, 0),
            insn(ebpf::JA, 0, 0, 1, 0),
            insn(ebpf::EXIT, 0, 0, 0, 0),
            insn(ebpf::MOV64_REG, 0, 2, 0, 0),
            insn(ebpf::EXIT, 0, 0, 0, 0),
        ],
        SBPFVersion::V2,
    );
    let fixed = Analysis::from_executable(&exe).unwrap();
    assert!(!entry_read(&fixed, 3, 2));
    assert!(fixed.dfg_forward_edges[&DfgNode::InstructionNode(0)]
        .iter()
        .any(|edge| edge.resource == DataResource::Register(2)
            && edge.destination == DfgNode::InstructionNode(3)
            && edge.kind == DfgEdgeKind::Filled));
}

#[test]
fn legacy_entry_reads_are_preserved() {
    let exe = executable(
        &[
            insn(ebpf::ST_DW_REG, 10, 4, -0xa8, 0),
            insn(ebpf::ST_DW_REG, 10, 3, -0x90, 0),
            insn(ebpf::ST_DW_REG, 10, 1, -0xd8, 0),
            insn(ebpf::LD_DW_REG, 0, 5, -0xff8, 0),
            insn(ebpf::EXIT, 0, 0, 0, 0),
        ],
        SBPFVersion::V0,
    );
    let fixed = Analysis::from_executable(&exe).unwrap();
    assert!(entry_read(&fixed, 0, 4));
    assert!(entry_read(&fixed, 1, 3));
    assert!(entry_read(&fixed, 3, 5));
}

#[test]
fn jmp32_does_not_define_its_operands() {
    // These encodings overlap V2 PQR arithmetic, which does define dst.
    for version in [SBPFVersion::V3, SBPFVersion::V4] {
        for opcode in [ebpf::JEQ32_IMM, ebpf::JEQ32_REG] {
            let exe = executable(
                &[
                    insn(opcode, 2, 3, 1, 1),
                    insn(ebpf::MOV64_REG, 0, 2, 0, 0),
                    insn(ebpf::EXIT, 0, 0, 0, 0),
                ],
                version,
            );
            let analysis = Analysis::from_executable(&exe).unwrap();
            assert!(entry_read(&analysis, 0, 2));
            assert_eq!(entry_read(&analysis, 0, 3), opcode == ebpf::JEQ32_REG);
            assert!(!analysis
                .dfg_forward_edges
                .get(&DfgNode::InstructionNode(0))
                .is_some_and(|edges| edges
                    .iter()
                    .any(|edge| edge.resource == DataResource::Register(2)
                        && edge.kind == DfgEdgeKind::Filled)));
        }
    }
}

#[test]
fn v2_store_definition_reaches_memory_load() {
    for (store, load) in [
        (ebpf::ST_1B_REG, ebpf::LD_1B_REG),
        (ebpf::ST_2B_REG, ebpf::LD_2B_REG),
        (ebpf::ST_4B_REG, ebpf::LD_4B_REG),
        (ebpf::ST_8B_REG, ebpf::LD_8B_REG),
    ] {
        let exe = executable(
            &[
                insn(store, 1, 3, 0, 0),
                insn(load, 2, 1, 0, 0),
                insn(ebpf::EXIT, 0, 0, 0, 0),
            ],
            SBPFVersion::V2,
        );
        let analysis = Analysis::from_executable(&exe).unwrap();
        assert!(analysis.dfg_forward_edges[&DfgNode::InstructionNode(0)]
            .iter()
            .any(|edge| edge.resource == DataResource::Memory
                && edge.destination == DfgNode::InstructionNode(1)
                && edge.kind == DfgEdgeKind::Filled));
    }
}

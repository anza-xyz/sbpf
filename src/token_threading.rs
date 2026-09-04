//! Unified interpreter and JIT compiler based on [token threading](https://en.wikipedia.org/wiki/Threaded_code#Token_threading)

/* TODOs
- Instruction metering of syscalls
- EbpfVm::encrypted_host_address
- Config::instruction_meter_checkpoint_distance
- Bumper at the end in case there was no final exit
- Debug stepper
- Profiler stopwatch
*/

macro_rules! all_opcodes {
    ($call_imm:expr, $dst32:expr, $dst64:expr, $src32:expr, $src64:expr) => (concat!(
        // Opcodes 0x00
        util!("4_opcodes_invalid"),

        // ADD32_IMM
        util!("decode_imm", register_map!("scratch", 64)),
        "add ", $dst32, ", ", register_map!("scratch", 32), "\n",
        util!("epilog"),

        // JA
        util!("verify_insn_limit", register_map!("insn_ptr", 64)),
        util!("decode_offset", register_map!("scratch", 64)),
        "sub ", register_map!("insn_limit", 64), ", ", register_map!("insn_ptr", 64), "\n",
        "lea ", register_map!("insn_ptr", 64), ", [", register_map!("scratch", 64), " * 8 + ", register_map!("insn_ptr", 64), "]\n",
        "add ", register_map!("insn_limit", 64), ", ", register_map!("insn_ptr", 64), "\n",
        util!("epilog"),

        util!("1_opcode_invalid"),

        // ADD64_IMM
        util!("decode_imm", register_map!("scratch", 64)),
        "add ", $dst64, ", ", register_map!("scratch", 64), "\n",
        util!("epilog"),

        util!("4_opcodes_invalid"),

        // ADD32_REG
        "add ", $dst32, ", ", $src32, "\n",
        util!("epilog"),

        util!("1_opcode_invalid"),
        util!("1_opcode_invalid"),

        // ADD64_REG
        "add ", $dst64, ", ", $src64, "\n",
        util!("epilog"),

        // Opcodes 0x10
        util!("4_opcodes_invalid"),

        // SUB32_IMM
        util!("decode_imm", register_map!("scratch", 64)),
        "sub ", $dst32, ",", register_map!("scratch", 32), "\n",
        util!("epilog"),

        // JEQ64_IMM
        util!("decode_imm", register_map!("scratch", 64)),
        util!("conditional_branch", $dst64, register_map!("scratch", 64), "cmp", "e"),
        util!("epilog"),

        // JEQ32_IMM
        util!("decode_imm", register_map!("scratch", 64)),
        util!("conditional_branch", $dst32, register_map!("scratch", 32), "cmp", "e"),
        util!("epilog"),

        // SUB64_IMM
        util!("decode_imm", register_map!("scratch", 64)),
        "sub ", $dst64, ",", register_map!("scratch", 64), "\n",
        util!("epilog"),

        // LD_DW_IMM
        util!("decode_imm", register_map!("scratch", 64)),
        util!("verify_insn_limit", register_map!("insn_ptr", 64)),
        "mov ", $dst32, ",", register_map!("scratch", 32), "\n",
        "add ", register_map!("insn_limit", 64), ", 8\n",
        "add ", register_map!("insn_ptr", 64), ", 8\n",
        util!("decode_imm", register_map!("scratch", 64)),
        "shl ", register_map!("scratch", 64), ", 32\n",
        "or ", $dst64, ",", register_map!("scratch", 64), "\n",
        util!("epilog"),

        util!("1_opcode_invalid"),
        util!("1_opcode_invalid"),
        util!("1_opcode_invalid"),

        // SUB32_REG
        "sub ", $dst32, ", ", $src32, "\n",
        util!("epilog"),

        // JEQ64_REG
        util!("conditional_branch", $dst64, $src64, "cmp", "e"),
        util!("epilog"),

        // JEQ32_REG
        util!("conditional_branch", $dst32, $src32, "cmp", "e"),
        util!("epilog"),

        // SUB64_REG
        "sub ", $dst64, ", ", $src64, "\n",
        util!("epilog"),

        // Opcodes 0x20
        util!("4_opcodes_invalid"),

        // MUL32_IMM
        util!("decode_imm", register_map!("scratch", 64)),
        "imul ", $dst32, ",", register_map!("scratch", 32), "\n",
        "movsxd ", $dst64, ",", $dst32, "\n",
        util!("epilog"),

        // JGT64_IMM
        util!("decode_imm", register_map!("scratch", 64)),
        util!("conditional_branch", $dst64, register_map!("scratch", 64), "cmp", "a"),
        util!("epilog"),

        // JGT32_IMM
        util!("decode_imm", register_map!("scratch", 64)),
        util!("conditional_branch", $dst32, register_map!("scratch", 32), "cmp", "a"),
        util!("epilog"),

        // MUL64_IMM
        util!("decode_imm", register_map!("scratch", 64)),
        "imul ", $dst64, ",", register_map!("scratch", 64), "\n",
        util!("epilog"),

        util!("4_opcodes_invalid"),

        // MUL32_REG
        "imul ", $dst32, ", ", $src32, "\n",
        "movsxd ", $dst64, ",", $dst32, "\n",
        util!("epilog"),

        // JGT64_REG
        util!("conditional_branch", $dst64, $src64, "cmp", "a"),
        util!("epilog"),

        // JGT32_REG
        util!("conditional_branch", $dst32, $src32, "cmp", "a"),
        util!("epilog"),

        // MUL64_REG
        "imul ", $dst64, ", ", $src64, "\n",
        util!("epilog"),

        // Opcodes 0x30
        util!("4_opcodes_invalid"),

        // DIV32_IMM
        util!("decode_imm", register_map!("scratch", 64)),
        util!("division", $dst32, register_map!("scratch", 32), register_map!("scratch", 32), "eax", "eax"),
        util!("epilog"),

        // JGE64_IMM
        util!("decode_imm", register_map!("scratch", 64)),
        util!("conditional_branch", $dst64, register_map!("scratch", 64), "cmp", "ae"),
        util!("epilog"),

        // JGE32_IMM
        util!("decode_imm", register_map!("scratch", 64)),
        util!("conditional_branch", $dst32, register_map!("scratch", 32), "cmp", "ae"),
        util!("epilog"),

        // DIV64_IMM
        util!("decode_imm", register_map!("scratch", 64)),
        util!("division", $dst64, register_map!("scratch", 64), register_map!("scratch", 64), "rax", "rax"),
        util!("epilog"),

        util!("4_opcodes_invalid"),

        // DIV32_REG
        util!("verify_divisor", $src32),
        util!("division", $dst32, $src32, register_map!("scratch", 32), "eax", "eax"),
        util!("epilog"),

        // JGE64_REG
        util!("conditional_branch", $dst64, $src64, "cmp", "ae"),
        util!("epilog"),

        // JGE32_REG
        util!("conditional_branch", $dst32, $src32, "cmp", "ae"),
        util!("epilog"),

        // DIV64_REG
        util!("verify_divisor", $src64),
        util!("division", $dst64, $src64, register_map!("scratch", 64), "rax", "rax"),
        util!("epilog"),

        // Opcodes 0x40
        util!("4_opcodes_invalid"),

        // OR32_IMM
        util!("decode_imm", register_map!("scratch", 64)),
        "or ", $dst32, ",", register_map!("scratch", 32), "\n",
        util!("epilog"),

        // JSET64_IMM
        util!("decode_imm", register_map!("scratch", 64)),
        util!("conditional_branch", $dst64, register_map!("scratch", 64), "test", "ne"),
        util!("epilog"),

        // JSET32_IMM
        util!("decode_imm", register_map!("scratch", 64)),
        util!("conditional_branch", $dst32, register_map!("scratch", 32), "test", "ne"),
        util!("epilog"),

        // OR64_IMM
        util!("decode_imm", register_map!("scratch", 64)),
        "or ", $dst64, ",", register_map!("scratch", 64), "\n",
        util!("epilog"),

        util!("4_opcodes_invalid"),

        // OR32_REG
        "or ", $dst32, ", ", $src32, "\n",
        util!("epilog"),

        // JSET64_REG
        util!("conditional_branch", $dst64, $src64, "test", "ne"),
        util!("epilog"),

        // JSET32_REG
        util!("conditional_branch", $dst32, $src32, "test", "ne"),
        util!("epilog"),

        // OR64_REG
        "or ", $dst64, ", ", $src64, "\n",
        util!("epilog"),

        // Opcodes 0x50
        util!("4_opcodes_invalid"),

        // AND32_IMM
        util!("decode_imm", register_map!("scratch", 64)),
        "and ", $dst32, ",", register_map!("scratch", 32), "\n",
        util!("epilog"),

        // JNE64_IMM
        util!("decode_imm", register_map!("scratch", 64)),
        util!("conditional_branch", $dst64, register_map!("scratch", 64), "cmp", "ne"),
        util!("epilog"),

        // JNE32_IMM
        util!("decode_imm", register_map!("scratch", 64)),
        util!("conditional_branch", $dst32, register_map!("scratch", 32), "cmp", "ne"),
        util!("epilog"),

        // AND64_IMM
        util!("decode_imm", register_map!("scratch", 64)),
        "and ", $dst64, ",", register_map!("scratch", 64), "\n",
        util!("epilog"),

        util!("4_opcodes_invalid"),

        // AND32_REG
        "and ", $dst32, ", ", $src32, "\n",
        util!("epilog"),

        // JNE64_REG
        util!("conditional_branch", $dst64, $src64, "cmp", "ne"),
        util!("epilog"),

        // JNE32_REG
        util!("conditional_branch", $dst32, $src32, "cmp", "ne"),
        util!("epilog"),

        // AND64_REG
        "and ", $dst64, ", ", $src64, "\n",
        util!("epilog"),

        // Opcodes 0x60
        util!("1_opcode_invalid"),

        // LD_W_REG
        util!("load", $dst64, $src64, u32),
        util!("epilog"),

        // ST_W_IMM
        util!("decode_imm", register_map!("scratch", 64)),
        util!("store", $dst64, register_map!("scratch", 64), u32),
        util!("epilog"),

        // ST_W_REG
        util!("store", $dst64, $src64, u32),
        util!("epilog"),

        // LSH32_IMM
        util!("decode_imm", register_map!("scratch", 64)),
        util!("bitshift", $dst32, $dst64, register_map!("scratch", 64), register_map!("scratch", 32), "shl"),
        util!("epilog"),

        // JSGT64_IMM
        util!("decode_imm", register_map!("scratch", 64)),
        util!("conditional_branch", $dst64, register_map!("scratch", 64), "cmp", "g"),
        util!("epilog"),

        // JSGT32_IMM
        util!("decode_imm", register_map!("scratch", 64)),
        util!("conditional_branch", $dst32, register_map!("scratch", 32), "cmp", "g"),
        util!("epilog"),

        // LSH64_IMM
        util!("decode_imm", register_map!("scratch", 64)),
        util!("bitshift", $dst64, $dst64, register_map!("scratch", 64), register_map!("scratch", 64), "shl"),
        util!("epilog"),

        util!("1_opcode_invalid"),

        // LD_H_REG
        util!("load", $dst64, $src64, u16),
        util!("epilog"),

        // ST_H_IMM
        util!("decode_imm", register_map!("scratch", 64)),
        util!("store", $dst64, register_map!("scratch", 64), u16),
        util!("epilog"),

        // ST_H_REG
        util!("store", $dst64, $src64, u16),
        util!("epilog"),

        // LSH32_REG
        util!("bitshift", $dst32, $dst64, $src64, register_map!("scratch", 32), "shl"),
        util!("epilog"),

        // JSGT64_REG
        util!("conditional_branch", $dst64, $src64, "cmp", "g"),
        util!("epilog"),

        // JSGT32_REG
        util!("conditional_branch", $dst32, $src32, "cmp", "g"),
        util!("epilog"),

        // LSH64_REG
        util!("bitshift", $dst64, $dst64, $src64, register_map!("scratch", 64), "shl"),
        util!("epilog"),

        // Opcodes 0x70
        util!("1_opcode_invalid"),

        // LD_B_REG
        util!("load", $dst64, $src64, u8),
        util!("epilog"),

        // ST_B_IMM
        util!("decode_imm", register_map!("scratch", 64)),
        util!("store", $dst64, register_map!("scratch", 64), u8),
        util!("epilog"),

        // ST_B_REG
        util!("store", $dst64, $src64, u8),
        util!("epilog"),

        // RSH32_IMM
        util!("decode_imm", register_map!("scratch", 64)),
        util!("bitshift", $dst32, $dst64, register_map!("scratch", 64), register_map!("scratch", 32), "shr"),
        util!("epilog"),

        // JSGE64_IMM
        util!("decode_imm", register_map!("scratch", 64)),
        util!("conditional_branch", $dst64, register_map!("scratch", 64), "cmp", "ge"),
        util!("epilog"),

        // JSGE32_IMM
        util!("decode_imm", register_map!("scratch", 64)),
        util!("conditional_branch", $dst32, register_map!("scratch", 32), "cmp", "ge"),
        util!("epilog"),

        // RSH64_IMM
        util!("decode_imm", register_map!("scratch", 64)),
        util!("bitshift", $dst64, $dst64, register_map!("scratch", 64), register_map!("scratch", 64), "shr"),
        util!("epilog"),

        util!("1_opcode_invalid"),

        // LD_DW_REG
        util!("load", $dst64, $src64, u64),
        util!("epilog"),

        // ST_DW_IMM
        util!("decode_imm", register_map!("scratch", 64)),
        util!("store", $dst64, register_map!("scratch", 64), u64),
        util!("epilog"),

        // ST_DW_REG
        util!("store", $dst64, $src64, u64),
        util!("epilog"),

        // RSH32_REG
        util!("bitshift", $dst32, $dst64, $src64, register_map!("scratch", 32), "shr"),
        util!("epilog"),

        // JSGE64_REG
        util!("conditional_branch", $dst64, $src64, "cmp", "ge"),
        util!("epilog"),

        // JSGE32_REG
        util!("conditional_branch", $dst32, $src32, "cmp", "ge"),
        util!("epilog"),

        // RSH64_REG
        util!("bitshift", $dst64, $dst64, $src64, register_map!("scratch", 64), "shr"),
        util!("epilog"),

        // Opcodes 0x80
        util!("4_opcodes_invalid"),

        // NEG32
        "neg ", $dst32, "\n",
        util!("epilog"),

        // CALL_IMM
        "jmp ", $call_imm, "\n",
        util!("epilog"),

        util!("1_opcode_invalid"),

        // NEG64
        "neg ", $dst64, "\n",
        util!("epilog"),

        util!("4_opcodes_invalid"),

        util!("1_opcode_invalid"),

        // CALL_REG
        "mov ", register_map!("scratch", 64), ", ", $dst64, "\n",
        "shr ", register_map!("scratch", 64), ", 32\n",
        "cmp ", register_map!("scratch", 64), ", 1\n",
        "jne call_outside_text_segment\n",
        "mov ", register_map!("scratch", 32), ", ", $dst32, "\n",
        "and ", register_map!("scratch", 32), ", -8\n",
        "cmp ", register_map!("scratch", 64), ", ", util!("slot_in_vm", "{vm_slot_program_slice} + 0x08"), "\n",
        "jae call_outside_text_segment\n",
        "add ", register_map!("scratch", 64), ", ", util!("slot_in_vm", "{vm_slot_program_slice} + 0x00"), "\n",
        "jmp subroutine_internal_call\n",
        "add ", register_map!("insn_ptr", 64), ", 8\n",
        ".align 64\n",

        util!("1_opcode_invalid"),
        util!("1_opcode_invalid"),

        // Opcodes 0x90
        util!("4_opcodes_invalid"),

        // MOD32_IMM
        util!("decode_imm", register_map!("scratch", 64)),
        util!("division", $dst32, register_map!("scratch", 32), register_map!("scratch", 32), "eax", "edx"),
        util!("epilog"),

        // EXIT
        util!("verify_insn_limit", register_map!("insn_ptr", 64)),
        "sub ", register_map!("insn_limit", 64), ", ", register_map!("insn_ptr", 64), "\n",
        "ret\n",
        util!("epilog"),

        util!("1_opcode_invalid"),

        // MOD64_IMM
        util!("decode_imm", register_map!("scratch", 64)),
        util!("division", $dst64, register_map!("scratch", 64), register_map!("scratch", 64), "rax", "rdx"),
        util!("epilog"),

        util!("4_opcodes_invalid"),

        // MOD32_REG
        util!("verify_divisor", $src32),
        util!("division", $dst32, $src32, register_map!("scratch", 32), "eax", "edx"),
        util!("epilog"),

        util!("1_opcode_invalid"),
        util!("1_opcode_invalid"),

        // MOD64_REG
        util!("verify_divisor", $src64),
        util!("division", $dst64, $src64, register_map!("scratch", 64), "rax", "rdx"),
        util!("epilog"),

        // Opcodes 0xA0
        util!("4_opcodes_invalid"),

        // XOR32_IMM
        util!("decode_imm", register_map!("scratch", 64)),
        "xor ", $dst32, ",", register_map!("scratch", 32), "\n",
        util!("epilog"),

        // JLT64_IMM
        util!("decode_imm", register_map!("scratch", 64)),
        util!("conditional_branch", $dst64, register_map!("scratch", 64), "cmp", "b"),
        util!("epilog"),

        // JLT32_IMM
        util!("decode_imm", register_map!("scratch", 64)),
        util!("conditional_branch", $dst32, register_map!("scratch", 32), "cmp", "b"),
        util!("epilog"),

        // XOR64_IMM
        util!("decode_imm", register_map!("scratch", 64)),
        "xor ", $dst64, ",", register_map!("scratch", 64), "\n",
        util!("epilog"),

        util!("4_opcodes_invalid"),

        // XOR32_REG
        "xor ", $dst32, ", ", $src32, "\n",
        util!("epilog"),

        // JLT64_REG
        util!("conditional_branch", $dst64, $src64, "cmp", "b"),
        util!("epilog"),

        // JLT32_REG
        util!("conditional_branch", $dst32, $src32, "cmp", "b"),
        util!("epilog"),

        // XOR64_REG
        "xor ", $dst64, ", ", $src64, "\n",
        util!("epilog"),

        // Opcodes 0xB0
        util!("4_opcodes_invalid"),

        // MOV32_IMM
        util!("decode_imm", register_map!("scratch", 64)),
        "mov ", $dst32, ",", register_map!("scratch", 32), "\n",
        util!("epilog"),

        // JLE64_IMM
        util!("decode_imm", register_map!("scratch", 64)),
        util!("conditional_branch", $dst64, register_map!("scratch", 64), "cmp", "be"),
        util!("epilog"),

        // JLE32_IMM
        util!("decode_imm", register_map!("scratch", 64)),
        util!("conditional_branch", $dst32, register_map!("scratch", 32), "cmp", "be"),
        util!("epilog"),

        // MOV64_IMM
        util!("decode_imm", register_map!("scratch", 64)),
        "mov ", $dst64, ",", register_map!("scratch", 64), "\n",
        util!("epilog"),

        util!("4_opcodes_invalid"),

        // MOV32_REG
        "mov ", $dst32, ", ", $src32, "\n",
        util!("epilog"),

        // JLE64_REG
        util!("conditional_branch", $dst64, $src64, "cmp", "be"),
        util!("epilog"),

        // JLE32_REG
        util!("conditional_branch", $dst32, $src32, "cmp", "be"),
        util!("epilog"),

        // MOV64_REG
        "mov ", $dst64, ", ", $src64, "\n",
        util!("epilog"),

        // Opcodes 0xC0
        util!("4_opcodes_invalid"),

        // ARSH32_IMM
        util!("decode_imm", register_map!("scratch", 64)),
        util!("bitshift", $dst32, $dst64, register_map!("scratch", 64), register_map!("scratch", 32), "sar"),
        util!("epilog"),

        // JSLT64_IMM
        util!("decode_imm", register_map!("scratch", 64)),
        util!("conditional_branch", $dst64, register_map!("scratch", 64), "cmp", "l"),
        util!("epilog"),

        // JSLT32_IMM
        util!("decode_imm", register_map!("scratch", 64)),
        util!("conditional_branch", $dst32, register_map!("scratch", 32), "cmp", "l"),
        util!("epilog"),

        // ARSH64_IMM
        util!("decode_imm", register_map!("scratch", 64)),
        util!("bitshift", $dst64, $dst64, register_map!("scratch", 64), register_map!("scratch", 64), "sar"),
        util!("epilog"),

        util!("4_opcodes_invalid"),

        // ARSH32_REG
        util!("bitshift", $dst32, $dst64, $src64, register_map!("scratch", 32), "sar"),
        util!("epilog"),

        // JSLT64_REG
        util!("conditional_branch", $dst64, $src64, "cmp", "l"),
        util!("epilog"),

        // JSLT32_REG
        util!("conditional_branch", $dst32, $src32, "cmp", "l"),
        util!("epilog"),

        // ARSH64_REG
        util!("bitshift", $dst64, $dst64, $src64, register_map!("scratch", 64), "sar"),
        util!("epilog"),

        // Opcodes 0xD0
        util!("4_opcodes_invalid"),

        // LE
        util!("decode_imm", register_map!("scratch", 64)),
        "mov ", register_map!("scratch", 64), ", ", $dst64, "\n",
        "call subroutine_le\n",
        "mov ", $dst64, ", ", register_map!("scratch", 64), "\n",
        util!("epilog"),

        // JSLE64_IMM
        util!("decode_imm", register_map!("scratch", 64)),
        util!("conditional_branch", $dst64, register_map!("scratch", 64), "cmp", "le"),
        util!("epilog"),

        // JSLE32_IMM
        util!("decode_imm", register_map!("scratch", 64)),
        util!("conditional_branch", $dst32, register_map!("scratch", 32), "cmp", "le"),
        util!("epilog"),

        util!("1_opcode_invalid"),
        util!("4_opcodes_invalid"),

        // BE
        util!("decode_imm", register_map!("scratch", 64)),
        "mov ", register_map!("scratch", 64), ", ", $dst64, "\n",
        "call subroutine_be\n",
        "mov ", $dst64, ", ", register_map!("scratch", 64), "\n",
        util!("epilog"),

        // JSLT64_REG
        util!("conditional_branch", $dst64, $src64, "cmp", "le"),
        util!("epilog"),

        // JSLT32_REG
        util!("conditional_branch", $dst32, $src32, "cmp", "le"),
        util!("epilog"),

        util!("1_opcode_invalid"),

        // Opcodes 0xE0
        util!("16_opcodes_invalid"),

        // Opcodes 0xF0
        util!("16_opcodes_invalid"),
    ));
}

#[cfg(feature = "tracer")]
macro_rules! call_subroutine_trace {
    () => ("call subroutine_trace\n");
}

#[cfg(not(feature = "tracer"))]
macro_rules! call_subroutine_trace {
    () => ("");
}

macro_rules! util {
    ("decode_opcode", $target:expr) => (concat!(
        "movzx ", $target, ", word ptr [", register_map!("insn_ptr", 64), "]\n",
        "shl ", $target, ", 6\n",
        "add ", $target, ", ", util!("slot_in_vm", "{vm_slot_stopwatch_numerator}"), "\n",
        // ".byte 0x49\n.byte 0x81\n.byte 0xC3\n.long [{instruction_templates} - .]\n", // "add r11, {instruction_templates} - .\n"
        // "lea rbp, [rip + {instruction_templates}]\n",
        // "add ", $target, ", rbp\n",
    ));
    ("decode_offset", $dst64:expr) => (concat!(
        "movsx ", $dst64, ", word ptr [", register_map!("insn_ptr", 64), " + 2]\n"
    ));
    ("decode_imm", $dst64:expr) => (concat!(
        "movsxd ", $dst64, ", dword ptr [", register_map!("insn_ptr", 64), " + 4]\n"
    ));
    ("epilog") => (concat!(
        "add ", register_map!("insn_ptr", 64), ", 8\n",
        call_subroutine_trace!(),
        util!("decode_opcode", register_map!("scratch", 64)),
        "jmp ", register_map!("scratch", 64), "\n",
        ".align 64\n",
    ));
    ("verify_divisor", $dst:expr) => (concat!(
        "cmp ", $dst, ", 0\n",
        "je divide_by_zero\n",
    ));
    ("verify_insn_limit", $insn_ptr:expr) => (concat!(
        "cmp ", $insn_ptr, ", ", register_map!("insn_limit", 64), "\n",
        "jae exceeded_max_instructions\n",
    ));
    ("division", $dst:expr, $src:expr, $scratch:expr, $dividend:expr, $quotient_or_remainder:expr) => (concat!(
        "push rax\n",
        "push rdx\n",
        "mov ", $scratch, ", ", $src, "\n",
        "mov ", $dividend, ", ", $dst, "\n",
        "xor rdx, rdx\n",
        "div ", $scratch, "\n",
        "mov ", $scratch, ", ", $quotient_or_remainder, "\n",
        "pop rdx\n",
        "pop rax\n",
        "mov ", $dst, ", ", $scratch, "\n",
    ));
    ("bitshift", $dst:expr, $dst64:expr, $src64:expr, $scratch:expr, $shift_type:expr) => (concat!(
        "push rcx\n",
        "push ", $dst64, "\n",
        "mov rcx, ", $src64, "\n",
        "pop ", register_map!("scratch", 64), "\n",
        $shift_type, " ", $scratch, ", cl\n",
        "pop rcx\n",
        "mov ", $dst, ", ", $scratch, "\n",
    ));
    ("load", $dst64:expr, $src64:expr, $type:ty) => (concat!(
        util!("decode_offset", register_map!("scratch", 64)),
        "add ", register_map!("scratch", 64), ", ", $src64, "\n",
        "push ", register_map!("scratch", 64), "\n",
        "call subroutine_load_", stringify!($type), "\n",
        "pop ", $dst64, "\n",
    ));
    ("store", $dst64:expr, $src64:expr, $type:ty) => (concat!(
        "push ", $src64, "\n",
        util!("decode_offset", register_map!("scratch", 64)),
        "add ", register_map!("scratch", 64), ", ", $dst64, "\n",
        "push ", register_map!("scratch", 64), "\n",
        "call subroutine_store_", stringify!($type), "\n",
        "add rsp, 0x10\n",
    ));
    ("conditional_branch", $dst:expr, $src:expr, $compare_or_test:expr, $condition:expr) => (concat!(
        util!("verify_insn_limit", register_map!("insn_ptr", 64)),
        "sub ", register_map!("insn_limit", 64), ", ", register_map!("insn_ptr", 64), "\n",
        $compare_or_test, " ", $dst, ", ", $src, "\n",
        util!("decode_offset", register_map!("scratch", 64)),
        "lea ", register_map!("scratch", 64), ", [", register_map!("scratch", 64), " * 8 + ", register_map!("insn_ptr", 64), "]\n",
        "cmov", $condition, " ", register_map!("insn_ptr", 64), ", ", register_map!("scratch", 64), "\n",
        "add ", register_map!("insn_limit", 64), ", ", register_map!("insn_ptr", 64), "\n",
    ));
    ("rust_call", $target:expr, $(arg($($arguments:expr),*),)* $(result($($result:expr),*),)?) => (concat!(
        "push ", register_map!("r0", 64), "\n",
        "push ", register_map!("r1", 64), "\n",
        "push ", register_map!("r2", 64), "\n",
        "push ", register_map!("r3", 64), "\n",
        "push ", register_map!("r4", 64), "\n",
        "push ", register_map!("r5", 64), "\n",
        "push ", register_map!("insn_ptr", 64), "\n",
        "push ", register_map!("insn_limit", 64), "\n",
        $($($arguments),*,)*
        "call ", $target, "\n",
        $($($result),*,)?
        "pop ", register_map!("insn_limit", 64), "\n",
        "pop ", register_map!("insn_ptr", 64), "\n",
        "pop ", register_map!("r5", 64), "\n",
        "pop ", register_map!("r4", 64), "\n",
        "pop ", register_map!("r3", 64), "\n",
        "pop ", register_map!("r2", 64), "\n",
        "pop ", register_map!("r1", 64), "\n",
        "pop ", register_map!("r0", 64), "\n",
    ));
    ("subroutine_load", $type:ty) => (concat!(
        "subroutine_load_", stringify!($type), ":\n",
        "rdgsbase ", register_map!("scratch", 64), "\n",
        util!("rust_call", concat!("{memory_mapping_load_", stringify!($type), "}"),
            arg("lea ", register_map!("r0", 64), ", [", register_map!("scratch", 64), " + {vm_slot_program_result}]\n"),
            arg("mov ", register_map!("r1", 64), ", ", util!("slot_in_vm", "{vm_slot_memory_mapping}"), "\n"),
            arg("mov ", register_map!("r2", 64), ", [rsp + 0x48]\n"),
        ),
        "cmp ", util!("slot_in_vm", "{vm_slot_program_result} + 0x00"), ", {program_result_err}\n",
        "je error_handler_epilog\n",
        "mov ", register_map!("scratch", 64), ", [", register_map!("scratch", 64), " + {vm_slot_program_result} + 0x08]\n",
        "mov [rsp + 0x08], ", register_map!("scratch", 64), "\n",
        "ret\n",
    ));
    ("subroutine_store", $type:ty) => (concat!(
        "subroutine_store_", stringify!($type), ":\n",
        "rdgsbase ", register_map!("scratch", 64), "\n",
        util!("rust_call", concat!("{memory_mapping_store_", stringify!($type), "}"),
            arg("lea ", register_map!("r0", 64), ", [", register_map!("scratch", 64), " + {vm_slot_program_result}]\n"),
            arg("mov ", register_map!("r1", 64), ", ", util!("slot_in_vm", "{vm_slot_memory_mapping}"), "\n"),
            arg("mov ", register_map!("r2", 64), ", [rsp + 0x50]\n"),
            arg("mov ", register_map!("r3", 64), ", [rsp + 0x48]\n"),
        ),
        "cmp ", util!("slot_in_vm", "{vm_slot_program_result} + 0x00"), ", {program_result_err}\n",
        "je error_handler_epilog\n",
        "ret\n",
    ));
    ("slot_in_vm", $slot_offset:expr) => (concat!(
        "qword ptr gs:[", $slot_offset, "]"
    ));
    ("error_handler", $err:literal) => (concat!(
        $err, ":\n",
        util!("verify_insn_limit", register_map!("insn_ptr", 64)),
        "mov ", util!("slot_in_vm", "{vm_slot_program_result} + 0x00"), ", {program_result_err}\n",
        "mov ", util!("slot_in_vm", "{vm_slot_program_result} + 0x08"), ", {", $err, "}\n",
        "jmp error_handler_epilog\n",
    ));
    ("1_opcode_invalid") => (
        "jmp unsupported_instruction\n.align 64\n"
    );
    ("4_opcodes_invalid") => (concat!(
        util!("1_opcode_invalid"),
        util!("1_opcode_invalid"),
        util!("1_opcode_invalid"),
        util!("1_opcode_invalid"),
    ));
    ("16_opcodes_invalid") => (concat!(
        util!("4_opcodes_invalid"),
        util!("4_opcodes_invalid"),
        util!("4_opcodes_invalid"),
        util!("4_opcodes_invalid"),
    ));
    ("64_opcodes_invalid") => (concat!(
        util!("16_opcodes_invalid"),
        util!("16_opcodes_invalid"),
        util!("16_opcodes_invalid"),
        util!("16_opcodes_invalid"),
    ));
    ("256_opcodes_invalid") => (concat!(
        util!("64_opcodes_invalid"),
        util!("64_opcodes_invalid"),
        util!("64_opcodes_invalid"),
        util!("64_opcodes_invalid"),
    ));
    ("1024_opcodes_invalid") => (concat!(
        util!("256_opcodes_invalid"),
        util!("256_opcodes_invalid"),
        util!("256_opcodes_invalid"),
        util!("256_opcodes_invalid"),
    ));
    ("4096_opcodes_invalid") => (concat!(
        util!("1024_opcodes_invalid"),
        util!("1024_opcodes_invalid"),
        util!("1024_opcodes_invalid"),
        util!("1024_opcodes_invalid"),
    ));
}

macro_rules! register_map {
    ("r0", 16) => ("di"); ("r0", 32) => ("edi"); ("r0", 64) => ("rdi");
    ("r1", 16) => ("si"); ("r1", 32) => ("esi"); ("r1", 64) => ("rsi");
    ("r2", 16) => ("dx"); ("r2", 32) => ("edx"); ("r2", 64) => ("rdx");
    ("r3", 16) => ("cx"); ("r3", 32) => ("ecx"); ("r3", 64) => ("rcx");
    ("r4", 16) => ("r8w"); ("r4", 32) => ("r8d"); ("r4", 64) => ("r8");
    ("r5", 16) => ("r9w"); ("r5", 32) => ("r9d"); ("r5", 64) => ("r9");
    ("r6", 16) => ("bx"); ("r6", 32) => ("ebx"); ("r6", 64) => ("rbx");
    ("r7", 16) => ("r12w"); ("r7", 32) => ("r12d"); ("r7", 64) => ("r12");
    ("r8", 16) => ("r13w"); ("r8", 32) => ("r13d"); ("r8", 64) => ("r13");
    ("r9", 16) => ("r14w"); ("r9", 32) => ("r14d"); ("r9", 64) => ("r14");
    ("r10", 16) => ("r15w"); ("r10", 32) => ("r15d"); ("r10", 64) => ("r15");

    // ("vm_ptr", 64) => ("gs_base");
    ("insn_ptr", 16) => ("ax"); ("insn_ptr", 32) => ("eax"); ("insn_ptr", 64) => ("rax");
    ("insn_limit", 16) => ("r10w"); ("insn_limit", 32) => ("r10d"); ("insn_limit", 64) => ("r10");
    ("scratch", 16) => ("r11w"); ("scratch", 32) => ("r11d"); ("scratch", 64) => ("r11");
}

macro_rules! all_src_and_dst_regs_and_opcodes {
    ($call_imm:expr, $src32:expr, $src64:expr) => (concat!(
        all_opcodes!($call_imm, register_map!("r0", 32), register_map!("r0", 64), $src32, $src64),
        all_opcodes!($call_imm, register_map!("r1", 32), register_map!("r1", 64), $src32, $src64),
        all_opcodes!($call_imm, register_map!("r2", 32), register_map!("r2", 64), $src32, $src64),
        all_opcodes!($call_imm, register_map!("r3", 32), register_map!("r3", 64), $src32, $src64),
        all_opcodes!($call_imm, register_map!("r4", 32), register_map!("r4", 64), $src32, $src64),
        all_opcodes!($call_imm, register_map!("r5", 32), register_map!("r5", 64), $src32, $src64),
        all_opcodes!($call_imm, register_map!("r6", 32), register_map!("r6", 64), $src32, $src64),
        all_opcodes!($call_imm, register_map!("r7", 32), register_map!("r7", 64), $src32, $src64),
        all_opcodes!($call_imm, register_map!("r8", 32), register_map!("r8", 64), $src32, $src64),
        all_opcodes!($call_imm, register_map!("r9", 32), register_map!("r9", 64), $src32, $src64),
        all_opcodes!($call_imm, register_map!("r10", 32), register_map!("r10", 64), $src32, $src64),
        util!("256_opcodes_invalid"),
        util!("256_opcodes_invalid"),
        util!("256_opcodes_invalid"),
        util!("256_opcodes_invalid"),
        util!("256_opcodes_invalid"),
    ));
    () => (concat!(
        all_src_and_dst_regs_and_opcodes!("subroutine_external_call", register_map!("r0", 32), register_map!("r0", 64)),
        all_src_and_dst_regs_and_opcodes!("subroutine_internal_call_imm", register_map!("r1", 32), register_map!("r1", 64)),
        all_src_and_dst_regs_and_opcodes!("unsupported_instruction", register_map!("r2", 32), register_map!("r2", 64)),
        all_src_and_dst_regs_and_opcodes!("unsupported_instruction", register_map!("r3", 32), register_map!("r3", 64)),
        all_src_and_dst_regs_and_opcodes!("unsupported_instruction", register_map!("r4", 32), register_map!("r4", 64)),
        all_src_and_dst_regs_and_opcodes!("unsupported_instruction", register_map!("r5", 32), register_map!("r5", 64)),
        all_src_and_dst_regs_and_opcodes!("unsupported_instruction", register_map!("r6", 32), register_map!("r6", 64)),
        all_src_and_dst_regs_and_opcodes!("unsupported_instruction", register_map!("r7", 32), register_map!("r7", 64)),
        all_src_and_dst_regs_and_opcodes!("unsupported_instruction", register_map!("r8", 32), register_map!("r8", 64)),
        all_src_and_dst_regs_and_opcodes!("unsupported_instruction", register_map!("r9", 32), register_map!("r9", 64)),
        all_src_and_dst_regs_and_opcodes!("unsupported_instruction", register_map!("r10", 32), register_map!("r10", 64)),
        util!("4096_opcodes_invalid"),
        util!("4096_opcodes_invalid"),
        util!("4096_opcodes_invalid"),
        util!("4096_opcodes_invalid"),
        util!("4096_opcodes_invalid"),
    ));
}

#[cfg(test)]
const _: &str = all_src_and_dst_regs_and_opcodes!();
#[cfg(not(test))]
use {crate::{error::{EbpfError, ProgramResult}, memory_region::MemoryMapping, program::BuiltinProgram, static_analysis::RegisterTraceEntry, vm::RuntimeEnvironmentSlot}, std::sync::Arc};
use crate::{static_analysis::DummyContextObject, vm::EbpfVm};

#[allow(dead_code)]
extern "Rust" {
    fn instruction_templates();
    fn interpreter_entrypoint(vm: *mut EbpfVm<DummyContextObject>);
}
const INSTRUCTION_TEMPLATES: unsafe extern "Rust" fn() = instruction_templates as unsafe extern "Rust" fn();
pub(crate) const INTERPRETER: unsafe extern "Rust" fn(*mut EbpfVm<DummyContextObject>) = interpreter_entrypoint as unsafe extern "Rust" fn(*mut EbpfVm<DummyContextObject>);

#[cfg(not(test))]
fn syscall_resolver(loader: &Arc<BuiltinProgram<DummyContextObject>>, key: u32) -> ProgramResult {
    loader.get_function_registry().lookup_by_key(key).map(|(_, (callback, _))| callback as usize as u64).ok_or(EbpfError::UnsupportedInstruction).into()
}

#[cfg(not(test))]
std::arch::global_asm!(concat!(
    ".global {instruction_templates}
    {instruction_templates}:\n",
    all_src_and_dst_regs_and_opcodes!(),

    "subroutine_external_call:\n",
    util!("verify_insn_limit", register_map!("insn_ptr", 64)),
    util!("decode_imm", register_map!("scratch", 64)),
    "mov [rsp - 0x48], ", register_map!("scratch", 64), "\n",
    "rdgsbase ", register_map!("scratch", 64), "\n",
    util!("rust_call", "{syscall_resolver}",
        arg("lea ", register_map!("r0", 64), ", [", register_map!("scratch", 64), " + {vm_slot_program_result}]\n"),
        arg("lea ", register_map!("r1", 64), ", [", register_map!("scratch", 64), " + {vm_slot_loader}]\n"),
        arg("mov ", register_map!("r2", 64), ", [rsp - 0x08]\n"),
    ),
    "cmp ", util!("slot_in_vm", "{vm_slot_program_result} + 0x00"), ", {program_result_err}\n",
    "je error_handler_epilog\n",
    "mov ", register_map!("scratch", 64), ", [", register_map!("scratch", 64), " + {vm_slot_program_result} + 0x08]\n",
    "subroutine_external_call_resolved:\n",
    "sub rsp, 0x10\n",
    "mov [rsp], ", register_map!("scratch", 64), "\n",
    "sub ", register_map!("insn_limit", 64), ", ", register_map!("insn_ptr", 64), "\n",
    "shr ", register_map!("insn_limit", 64), ", 3\n",
    "dec ", register_map!("insn_limit", 64), "\n",
    "mov ", util!("slot_in_vm", "{vm_slot_due_insn_count}"), ", ", register_map!("insn_limit", 64), "\n",
    "rdgsbase ", register_map!("scratch", 64), "\n",
    util!("rust_call", "{encrypted_host_address}",
        arg("mov ", register_map!("r0", 64), ", ", register_map!("scratch", 64), "\n"),
        result("mov ", register_map!("scratch", 64), ", rax\n"),
    ),
    util!("rust_call", "[rsp + 0x40]",
        arg("mov ", register_map!("r0", 64), ", ", register_map!("scratch", 64), "\n"),
    ),
    "add rsp, 0x10\n",
    "mov ", register_map!("insn_limit", 64), ", ", util!("slot_in_vm", "{vm_slot_previous_instruction_meter}"), "\n",
    "inc ", register_map!("insn_limit", 64), "\n",
    "shl ", register_map!("insn_limit", 64), ", 3\n",
    "add ", register_map!("insn_limit", 64), ", ", register_map!("insn_ptr", 64), "\n",
    "cmp ", util!("slot_in_vm", "{vm_slot_program_result} + 0x00"), ", {program_result_err}\n",
    "je error_handler_epilog\n",
    "mov ", register_map!("r0", 64), ", ", util!("slot_in_vm", "{vm_slot_program_result} + 0x08"), "\n",
    util!("epilog"),

    "subroutine_internal_call_imm:\n",
    util!("decode_imm", register_map!("scratch", 64)),
    "lea ", register_map!("scratch", 64), ", [", register_map!("scratch", 64), " * 8 + ", register_map!("insn_ptr", 64), " + 8]\n",
    "subroutine_internal_call:\n",
    "cmp ", register_map!("r10", 64), ", ", util!("slot_in_vm", "{vm_slot_call_depth}"), "\n",
    "jae call_depth_exeeded\n",
    "add ", register_map!("r10", 64), ", 0x1000\n",
    "push ", register_map!("insn_ptr", 64), "\n",
    "sub ", register_map!("insn_limit", 64), ", ", register_map!("insn_ptr", 64), "\n",
    "mov ", register_map!("insn_ptr", 64), ", ", register_map!("scratch", 64), "\n",
    "lea ", register_map!("insn_limit", 64), ", [", register_map!("insn_limit", 64), " + ", register_map!("insn_ptr", 64), " - 8]\n",
    util!("verify_insn_limit", register_map!("insn_ptr", 64)),
    "push ", register_map!("r9", 64), "\n",
    "push ", register_map!("r8", 64), "\n",
    "push ", register_map!("r7", 64), "\n",
    "push ", register_map!("r6", 64), "\n",
    call_subroutine_trace!(),
    util!("decode_opcode", register_map!("scratch", 64)),
    "call ", register_map!("scratch", 64), "\n",
    "pop ", register_map!("r6", 64), "\n",
    "pop ", register_map!("r7", 64), "\n",
    "pop ", register_map!("r8", 64), "\n",
    "pop ", register_map!("r9", 64), "\n",
    "sub ", register_map!("r10", 64), ", 0x1000\n",
    "pop ", register_map!("insn_ptr", 64), "\n",
    "add ", register_map!("insn_limit", 64), ", ", register_map!("insn_ptr", 64), "\n",
    util!("epilog"),

    util!("subroutine_load", u8),
    util!("subroutine_load", u16),
    util!("subroutine_load", u32),
    util!("subroutine_load", u64),
    util!("subroutine_store", u8),
    util!("subroutine_store", u16),
    util!("subroutine_store", u32),
    util!("subroutine_store", u64),

    "subroutine_trace:\n",
    "mov ", register_map!("scratch", 64), ", ", register_map!("insn_ptr", 64), "\n",
    "sub ", register_map!("scratch", 64), ", ", util!("slot_in_vm", "{vm_slot_program_slice} + 0x00"), "\n",
    "shr ", register_map!("scratch", 64), ", 3\n",
    "mov ", util!("slot_in_vm", "{vm_slot_registers} + 0x00"), ", ", register_map!("r0", 64), "\n",
    "mov ", util!("slot_in_vm", "{vm_slot_registers} + 0x08"), ", ", register_map!("r1", 64), "\n",
    "mov ", util!("slot_in_vm", "{vm_slot_registers} + 0x10"), ", ", register_map!("r2", 64), "\n",
    "mov ", util!("slot_in_vm", "{vm_slot_registers} + 0x18"), ", ", register_map!("r3", 64), "\n",
    "mov ", util!("slot_in_vm", "{vm_slot_registers} + 0x20"), ", ", register_map!("r4", 64), "\n",
    "mov ", util!("slot_in_vm", "{vm_slot_registers} + 0x28"), ", ", register_map!("r5", 64), "\n",
    "mov ", util!("slot_in_vm", "{vm_slot_registers} + 0x30"), ", ", register_map!("r6", 64), "\n",
    "mov ", util!("slot_in_vm", "{vm_slot_registers} + 0x38"), ", ", register_map!("r7", 64), "\n",
    "mov ", util!("slot_in_vm", "{vm_slot_registers} + 0x40"), ", ", register_map!("r8", 64), "\n",
    "mov ", util!("slot_in_vm", "{vm_slot_registers} + 0x48"), ", ", register_map!("r9", 64), "\n",
    "mov ", util!("slot_in_vm", "{vm_slot_registers} + 0x50"), ", ", register_map!("r10", 64), "\n",
    "mov ", util!("slot_in_vm", "{vm_slot_registers} + 0x58"), ", ", register_map!("scratch", 64), "\n",
    "rdgsbase ", register_map!("scratch", 64), "\n",
    util!("rust_call", "{register_trace_entry_push}",
        arg("lea ", register_map!("r0", 64), ", [", register_map!("scratch", 64), " + {vm_slot_register_trace}]\n"),
        arg("lea ", register_map!("r1", 64), ", [", register_map!("scratch", 64), " + {vm_slot_registers}]\n"),
    ),
    "ret\n",

    "subroutine_le:\n",
    "cmp dword ptr [", register_map!("insn_ptr", 64), " + 4], 16\n",
    "je 16f\n",
    "cmp dword ptr [", register_map!("insn_ptr", 64), " + 4], 32\n",
    "je 32f\n",
    "cmp dword ptr [", register_map!("insn_ptr", 64), " + 4], 64\n",
    "je 64f\n",
    "jmp unsupported_instruction\n",
    "16:\n",
    "movzx ", register_map!("scratch", 32), ",", register_map!("scratch", 16), "\n",
    "ret\n",
    "32:\n",
    "mov ", register_map!("scratch", 32), ",", register_map!("scratch", 32), "\n",
    "ret\n",
    "64:\n",
    "ret\n",

    "subroutine_be:\n",
    "cmp dword ptr [", register_map!("insn_ptr", 64), " + 4], 16\n",
    "je 16f\n",
    "cmp dword ptr [", register_map!("insn_ptr", 64), " + 4], 32\n",
    "je 32f\n",
    "cmp dword ptr [", register_map!("insn_ptr", 64), " + 4], 64\n",
    "je 64f\n",
    "jmp unsupported_instruction\n",
    "16:\n",
    "rol ", register_map!("scratch", 16), ", 8\n",
    "movzx ", register_map!("scratch", 32), ",", register_map!("scratch", 16), "\n",
    "ret\n",
    "32:\n",
    "bswap ", register_map!("scratch", 32), "\n",
    "ret\n",
    "64:\n",
    "bswap ", register_map!("scratch", 64), "\n",
    "ret\n",

    util!("error_handler", "call_depth_exeeded"),
    util!("error_handler", "call_outside_text_segment"),
    util!("error_handler", "divide_by_zero"),
    util!("error_handler", "divide_overflow"),
    util!("error_handler", "unsupported_instruction"),
    "exceeded_max_instructions:\n",
    "mov ", util!("slot_in_vm", "{vm_slot_program_result} + 0x00"), ", {program_result_err}\n",
    "mov ", util!("slot_in_vm", "{vm_slot_program_result} + 0x08"), ", {exceeded_max_instructions}\n",
    "error_handler_epilog:\n",
    "mov rsp, ", util!("slot_in_vm", "{vm_slot_host_stack_pointer}"), "\n",
    "sub ", register_map!("insn_limit", 64), ", ", register_map!("insn_ptr", 64), "\n",
    "jmp interpreter_exitpoint\n",

    ".global {interpreter_entrypoint}\n",
    "{interpreter_entrypoint}:\n",
    "push rbx\n",
    "push rbp\n",
    "push r12\n",
    "push r13\n",
    "push r14\n",
    "push r15\n",
    "wrgsbase ", register_map!("r0", 64), "\n",
    "mov ", util!("slot_in_vm", "{vm_slot_host_stack_pointer}"), ", rsp\n",
    "lea ", register_map!("scratch", 64), ", [rip + {instruction_templates}]\n",
    "mov ", util!("slot_in_vm", "{vm_slot_stopwatch_numerator}"), ", ", register_map!("scratch", 64), "\n",
    "mov ", register_map!("insn_ptr", 64), ", ", util!("slot_in_vm", "{vm_slot_registers} + 0x58"), "\n",
    "shl ", register_map!("insn_ptr", 64), ", 3\n",
    "add ", register_map!("insn_ptr", 64), ", ", util!("slot_in_vm", "{vm_slot_program_slice} + 0x00"), "\n",
    "mov ", register_map!("insn_limit", 64), ", ", util!("slot_in_vm", "{vm_slot_previous_instruction_meter}"), "\n",
    "shl ", register_map!("insn_limit", 64), ", 3\n",
    "add ", register_map!("insn_limit", 64), ", ", register_map!("insn_ptr", 64), "\n",
    "mov ", register_map!("r0", 64), ", ", util!("slot_in_vm", "{vm_slot_registers} + 0x00"), "\n",
    "mov ", register_map!("r1", 64), ", ", util!("slot_in_vm", "{vm_slot_registers} + 0x08"), "\n",
    "mov ", register_map!("r2", 64), ", ", util!("slot_in_vm", "{vm_slot_registers} + 0x10"), "\n",
    "mov ", register_map!("r3", 64), ", ", util!("slot_in_vm", "{vm_slot_registers} + 0x18"), "\n",
    "mov ", register_map!("r4", 64), ", ", util!("slot_in_vm", "{vm_slot_registers} + 0x20"), "\n",
    "mov ", register_map!("r5", 64), ", ", util!("slot_in_vm", "{vm_slot_registers} + 0x28"), "\n",
    "mov ", register_map!("r6", 64), ", ", util!("slot_in_vm", "{vm_slot_registers} + 0x30"), "\n",
    "mov ", register_map!("r7", 64), ", ", util!("slot_in_vm", "{vm_slot_registers} + 0x38"), "\n",
    "mov ", register_map!("r8", 64), ", ", util!("slot_in_vm", "{vm_slot_registers} + 0x40"), "\n",
    "mov ", register_map!("r9", 64), ", ", util!("slot_in_vm", "{vm_slot_registers} + 0x48"), "\n",
    "mov ", register_map!("r10", 64), ", ", util!("slot_in_vm", "{vm_slot_registers} + 0x50"), "\n",
    call_subroutine_trace!(),
    util!("decode_opcode", register_map!("scratch", 64)),
    "call ", register_map!("scratch", 64), "\n",
    "mov ", util!("slot_in_vm", "{vm_slot_program_result} + 0x00"), ", {program_result_ok}\n",
    "mov ", util!("slot_in_vm", "{vm_slot_program_result} + 0x08"), ", ", register_map!("r0", 64), "\n",
    "interpreter_exitpoint:\n",
    "mov ", register_map!("scratch", 64), ", ", register_map!("insn_ptr", 64), "\n",
    "sub ", register_map!("scratch", 64), ", ", util!("slot_in_vm", "{vm_slot_program_slice} + 0x00"), "\n",
    "shr ", register_map!("scratch", 64), ", 3\n",
    "mov ", util!("slot_in_vm", "{vm_slot_registers} + 0x58"), ", ", register_map!("scratch", 64), "\n",
    "shr ", register_map!("insn_limit", 64), ", 3\n",
    "mov ", register_map!("scratch", 64), ", ", util!("slot_in_vm", "{vm_slot_previous_instruction_meter}"), "\n",
    "sub ", register_map!("scratch", 64), ", ", register_map!("insn_limit", 64), "\n",
    "inc ", register_map!("scratch", 64), "\n",
    "mov ", util!("slot_in_vm", "{vm_slot_due_insn_count}"), ", ", register_map!("scratch", 64), "\n",
    "pop r15\n",
    "pop r14\n",
    "pop r13\n",
    "pop r12\n",
    "pop rbp\n",
    "pop rbx\n",
    "ret\n"),

    memory_mapping_load_u8 = sym MemoryMapping::load::<u8>,
    memory_mapping_load_u16 = sym MemoryMapping::load::<u16>,
    memory_mapping_load_u32 = sym MemoryMapping::load::<u32>,
    memory_mapping_load_u64 = sym MemoryMapping::load::<u64>,
    memory_mapping_store_u8 = sym MemoryMapping::store::<u8>,
    memory_mapping_store_u16 = sym MemoryMapping::store::<u16>,
    memory_mapping_store_u32 = sym MemoryMapping::store::<u32>,
    memory_mapping_store_u64 = sym MemoryMapping::store::<u64>,
    register_trace_entry_push = sym Vec::<RegisterTraceEntry>::push,
    instruction_templates = sym instruction_templates,
    interpreter_entrypoint = sym interpreter_entrypoint,
    syscall_resolver = sym syscall_resolver,
    encrypted_host_address = sym EbpfVm::<DummyContextObject>::encrypted_host_address,

    vm_slot_host_stack_pointer = const RuntimeEnvironmentSlot::HostStackPointer as usize,
    vm_slot_call_depth = const RuntimeEnvironmentSlot::CallDepth as usize,
    vm_slot_previous_instruction_meter = const RuntimeEnvironmentSlot::PreviousInstructionMeter as usize,
    vm_slot_due_insn_count = const RuntimeEnvironmentSlot::DueInsnCount as usize,
    vm_slot_stopwatch_numerator = const RuntimeEnvironmentSlot::StopwatchNumerator as usize,
    // vm_slot_stopwatch_denominator = const RuntimeEnvironmentSlot::StopwatchDenominator as usize,
    vm_slot_registers = const RuntimeEnvironmentSlot::Registers as usize,
    vm_slot_program_slice = const RuntimeEnvironmentSlot::ProgramSlice as usize,
    vm_slot_program_result = const RuntimeEnvironmentSlot::ProgramResult as usize,
    vm_slot_memory_mapping = const RuntimeEnvironmentSlot::MemoryMapping as usize,
    vm_slot_loader = const RuntimeEnvironmentSlot::Loader as usize,
    vm_slot_register_trace = const RuntimeEnvironmentSlot::RegisterTrace as usize,

    program_result_ok = const ProgramResult::Ok(0).discriminant(),
    program_result_err = const ProgramResult::Err(EbpfError::UnsupportedInstruction).discriminant(),
    exceeded_max_instructions = const EbpfError::ExceededMaxInstructions.discriminant(),
    call_depth_exeeded = const EbpfError::CallDepthExceeded.discriminant(),
    call_outside_text_segment = const EbpfError::CallOutsideTextSegment.discriminant(),
    divide_by_zero = const EbpfError::DivideByZero.discriminant(),
    divide_overflow = const EbpfError::DivideOverflow.discriminant(),
    unsupported_instruction = const EbpfError::UnsupportedInstruction.discriminant(),
);

const INSN_LEN: u8 = 0x3F;
const INSN_HAS_IMM: u8 = 0x40;
const INSN_HAS_OFF: u8 = 0x80;
const EPILOG_PATTERN: [u8; 4] = [0x48, 0x83, 0xC0, 0x08]; // add rax, 8
const DECODE_IMM_PATTERN: [u8; 4] = [0x4C, 0x63, 0x58, 0x04]; // movsxd r11, dword ptr [rax + 4]
const DECODE_OFF_PATTERN: [u8; 5] = [0x4C, 0x0F, 0xBF, 0x58, 0x02]; // movsx r11, word ptr [rax + 2]

fn get_instruction_template_metas() -> &'static [u8] {
    static INSTRUCTION_TEMPLATE_METAS: std::sync::OnceLock<Vec<u8>> = std::sync::OnceLock::new();
    INSTRUCTION_TEMPLATE_METAS.get_or_init(|| {
        let instruction_templates = unsafe { std::slice::from_raw_parts(INSTRUCTION_TEMPLATES as *const [u8; 64], 65536) };
        let mut empty_instruction_template: [u8; 64] = instruction_templates[0];
        let offset_to_unsupported_instruction_handler: u32 = unsafe { std::ptr::read_unaligned(empty_instruction_template.as_ptr().offset(1).cast::<u32>()) };
        instruction_templates.iter().enumerate().map(|(index, instruction_template)| {
            let target = offset_to_unsupported_instruction_handler - index as u32 * 64;
            unsafe { std::ptr::write_unaligned(empty_instruction_template.as_mut_ptr().offset(1).cast::<u32>(), target) };
            if instruction_template == &empty_instruction_template {
                0
            } else {
                let mut result = instruction_template.windows(EPILOG_PATTERN.len()).position(|window| window == &EPILOG_PATTERN).unwrap() as u8;
                let mut instruction_template = &instruction_template[0..result as usize];
                if &instruction_template[0..DECODE_IMM_PATTERN.len()] == &DECODE_IMM_PATTERN {
                    result |= INSN_HAS_IMM;
                    instruction_template = &instruction_template[4..];
                }
                if &instruction_template[0..DECODE_OFF_PATTERN.len()] == &DECODE_OFF_PATTERN {
                    result |= INSN_HAS_OFF;
                    // instruction_template = &instruction_template[5..];
                }
                if index & 0x07 < 4 { // TODO
                    assert_ne!(result & INSN_HAS_OFF, 0);
                }
                result
            }
        }).collect()
    })
}

/// Turns SBPF bytecode into an IP/PC mapping and x86-64 machinecode
pub fn compile(program: &[u64]) -> (Vec::<u32>, Vec::<u8>) {
    let instruction_templates = unsafe { std::slice::from_raw_parts(INSTRUCTION_TEMPLATES as *const [u8; 64], 65536) };
    let instruction_template_metas = get_instruction_template_metas();
    let mut position: u32 = 0;
    // First scan
    let mut pc_section = Vec::<u32>::with_capacity(program.len());
    for insn in program.iter() {
        let instruction_template_index = *insn as u16 as usize;
        let instruction_template_meta = instruction_template_metas[instruction_template_index];
        let mut instruction_length = (instruction_template_meta & INSN_LEN) as usize;
        instruction_length += (7 - DECODE_IMM_PATTERN.len()) * (instruction_template_meta & INSN_HAS_IMM != 0) as usize;
        instruction_length += (7 - DECODE_OFF_PATTERN.len()) * (instruction_template_meta & INSN_HAS_OFF != 0) as usize;
        if instruction_length > 0 {
            pc_section.push(position);
        }
        position += instruction_length as u32;
    }
    // Second scan
    let mut text_section = Vec::<u8>::with_capacity(position as usize);
    for (program_counter, insn) in program.iter().enumerate() {
        let opcode_class = (insn & 0x07) as u8;
        let instruction_template_index = *insn as u16 as usize;
        let instruction_template_meta = instruction_template_metas[instruction_template_index];
        let instruction_length = (instruction_template_meta & INSN_LEN) as usize;
        let mut instruction_template = &instruction_templates[instruction_template_index][0..instruction_length];
        if instruction_template_meta & INSN_HAS_IMM != 0 {
            text_section.extend(&[0x49, 0xC7, 0xC3, (insn >> 32) as u8, (insn >> 40) as u8, (insn >> 48) as u8, (insn >> 56) as u8]);
            instruction_template = &instruction_template[DECODE_IMM_PATTERN.len()..];
        }
        if instruction_template_meta & INSN_HAS_OFF != 0 {
            // TODO: Offset in store instruction is not directly behind immediate value
            text_section.extend(&[0x49, 0xC7, 0xC3, (insn >> 16) as u8, (insn >> 24) as u8, 0x00, 0x00]);
            instruction_template = &instruction_template[DECODE_OFF_PATTERN.len()..];
        }
        text_section.extend(instruction_template);
        if opcode_class == crate::ebpf::BPF_JMP32 || opcode_class == crate::ebpf::BPF_JMP64 {
            let target_program_counter = program_counter as i32 + ((insn >> 16) as i16 as i32);
            let offset = pc_section[target_program_counter as usize] as i32 - pc_section[program_counter] as i32;
            let text_section_end = text_section.len() - 4;
            text_section[text_section_end..].copy_from_slice(&[(offset >> 0) as u8, (offset >> 8) as u8, (offset >> 16) as u8, (offset >> 24) as u8]);
            // TODO: Resolve syscalls
        }
    }
    (pc_section, text_section)
}

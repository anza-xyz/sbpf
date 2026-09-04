//! Unified interpreter and JIT compiler based on [token threading](https://en.wikipedia.org/wiki/Threaded_code#Token_threading)

/* TODOs
- Call
- Callx
- Syscall
- Loads / stores
- Config::instruction_meter_checkpoint_distance
- Bumper in case there was no final exit
- Debug tracer
- Debug stepper
*/

macro_rules! all_opcodes {
    ($epilog:expr, $dst32:expr, $dst64:expr, $src32:expr, $src64:expr) => (concat!(
        // Opcodes 0x00
        util!("4_opcodes_invalid"),

        // ADD32_IMM
        util!("decode_imm", register_map!("scratch", 64)),
        "add ", $dst32, ", ", register_map!("scratch", 32), "\n",
        $epilog,

        // JA
        util!("decode_offset", register_map!("scratch", 64)),
        util!("verify_insn_limit", register_map!("insn_ptr", 64)),
        "sub ", register_map!("insn_limit", 64), ", ", register_map!("insn_ptr", 64), "\n",
        "lea ", register_map!("insn_ptr", 64), ", [", register_map!("scratch", 64), " * 8 + ", register_map!("insn_ptr", 64), "]\n",
        "add ", register_map!("insn_limit", 64), ", ", register_map!("insn_ptr", 64), "\n",
        $epilog,

        util!("1_opcode_invalid"),

        // ADD64_IMM
        util!("decode_imm", register_map!("scratch", 64)),
        "add ", $dst64, ", ", register_map!("scratch", 64), "\n",
        $epilog,

        util!("4_opcodes_invalid"),

        // ADD32_REG
        "add ", $dst32, ", ", $src32, "\n",
        $epilog,

        util!("1_opcode_invalid"),
        util!("1_opcode_invalid"),

        // ADD64_REG
        "add ", $dst64, ", ", $src64, "\n",
        $epilog,

        // Opcodes 0x10
        util!("4_opcodes_invalid"),

        // SUB32_IMM
        util!("decode_imm", register_map!("scratch", 64)),
        "sub ", $dst32, ",", register_map!("scratch", 32), "\n",
        $epilog,

        // JEQ64_IMM
        util!("decode_imm", register_map!("scratch", 64)),
        util!("conditional_branch", $dst64, register_map!("scratch", 64), "cmp", "e"),
        $epilog,

        // JEQ32_IMM
        util!("decode_imm", register_map!("scratch", 64)),
        util!("conditional_branch", $dst32, register_map!("scratch", 32), "cmp", "e"),
        $epilog,

        // SUB64_IMM
        util!("decode_imm", register_map!("scratch", 64)),
        "sub ", $dst64, ",", register_map!("scratch", 64), "\n",
        $epilog,

        // LD_DW_IMM
        util!("verify_insn_limit", register_map!("insn_ptr", 64)),
        util!("decode_imm", register_map!("scratch", 64)),
        "mov ", $dst64, ",", register_map!("scratch", 64), "\n",
        "add ", register_map!("insn_limit", 64), ", 8\n",
        "add ", register_map!("insn_ptr", 64), ", 8\n",
        util!("decode_imm", register_map!("scratch", 64)),
        "shl ", register_map!("scratch", 64), ", 32\n",
        "or ", $dst64, ",", register_map!("scratch", 64), "\n",
        $epilog,

        util!("1_opcode_invalid"),
        util!("1_opcode_invalid"),
        util!("1_opcode_invalid"),

        // SUB32_REG
        "sub ", $dst32, ", ", $src32, "\n",
        $epilog,

        // JEQ64_REG
        util!("conditional_branch", $dst64, $src64, "cmp", "e"),
        $epilog,

        // JEQ32_REG
        util!("conditional_branch", $dst32, $src32, "cmp", "e"),
        $epilog,

        // SUB64_REG
        "sub ", $dst64, ", ", $src64, "\n",
        $epilog,

        // Opcodes 0x20
        util!("4_opcodes_invalid"),

        // MUL32_IMM
        util!("decode_imm", register_map!("scratch", 64)),
        "imul ", $dst32, ",", register_map!("scratch", 32), "\n",
        $epilog,

        // JGT64_IMM
        util!("decode_imm", register_map!("scratch", 64)),
        util!("conditional_branch", $dst64, register_map!("scratch", 64), "cmp", "a"),
        $epilog,

        // JGT32_IMM
        util!("decode_imm", register_map!("scratch", 64)),
        util!("conditional_branch", $dst32, register_map!("scratch", 32), "cmp", "a"),
        $epilog,

        // MUL64_IMM
        util!("decode_imm", register_map!("scratch", 64)),
        "imul ", $dst64, ",", register_map!("scratch", 64), "\n",
        $epilog,

        util!("4_opcodes_invalid"),

        // MUL32_REG
        "imul ", $dst32, ", ", $src32, "\n",
        $epilog,

        // JGT64_REG
        util!("conditional_branch", $dst64, $src64, "cmp", "a"),
        $epilog,

        // JGT32_REG
        util!("conditional_branch", $dst32, $src32, "cmp", "a"),
        $epilog,

        // MUL64_REG
        "imul ", $dst64, ", ", $src64, "\n",
        $epilog,

        // Opcodes 0x30
        util!("4_opcodes_invalid"),

        // DIV32_IMM
        util!("decode_imm", register_map!("scratch", 64)),
        util!("verify_divisor", register_map!("scratch", 64)),
        util!("division", $dst32, register_map!("scratch", 32), register_map!("scratch", 32), "eax", "eax"),
        $epilog,

        // JGE64_IMM
        util!("decode_imm", register_map!("scratch", 64)),
        util!("conditional_branch", $dst64, register_map!("scratch", 64), "cmp", "ae"),
        $epilog,

        // JGE32_IMM
        util!("decode_imm", register_map!("scratch", 64)),
        util!("conditional_branch", $dst32, register_map!("scratch", 32), "cmp", "ae"),
        $epilog,

        // DIV64_IMM
        util!("decode_imm", register_map!("scratch", 64)),
        util!("verify_divisor", register_map!("scratch", 64)),
        util!("division", $dst64, register_map!("scratch", 64), register_map!("scratch", 64), "rax", "rax"),
        $epilog,

        util!("4_opcodes_invalid"),

        // DIV32_REG
        util!("division", $dst32, $src32, register_map!("scratch", 32), "eax", "eax"),
        $epilog,

        // JGE64_REG
        util!("conditional_branch", $dst64, $src64, "cmp", "ae"),
        $epilog,

        // JGE32_REG
        util!("conditional_branch", $dst32, $src32, "cmp", "ae"),
        $epilog,

        // DIV64_REG
        util!("division", $dst64, $src64, register_map!("scratch", 64), "rax", "rax"),
        $epilog,

        // Opcodes 0x40
        util!("4_opcodes_invalid"),

        // OR32_IMM
        util!("decode_imm", register_map!("scratch", 64)),
        "or ", $dst32, ",", register_map!("scratch", 32), "\n",
        $epilog,

        // JSET64_IMM
        util!("decode_imm", register_map!("scratch", 64)),
        util!("conditional_branch", $dst64, register_map!("scratch", 64), "test", "ne"),
        $epilog,

        // JSET32_IMM
        util!("decode_imm", register_map!("scratch", 64)),
        util!("conditional_branch", $dst32, register_map!("scratch", 32), "test", "ne"),
        $epilog,

        // OR64_IMM
        util!("decode_imm", register_map!("scratch", 64)),
        "or ", $dst64, ",", register_map!("scratch", 64), "\n",
        $epilog,

        util!("4_opcodes_invalid"),

        // OR32_REG
        "or ", $dst32, ", ", $src32, "\n",
        $epilog,

        // JSET64_REG
        util!("conditional_branch", $dst64, $src64, "test", "ne"),
        $epilog,

        // JSET32_REG
        util!("conditional_branch", $dst32, $src32, "test", "ne"),
        $epilog,

        // OR64_REG
        "or ", $dst64, ", ", $src64, "\n",
        $epilog,

        // Opcodes 0x50
        util!("4_opcodes_invalid"),

        // AND32_IMM
        util!("decode_imm", register_map!("scratch", 64)),
        "and ", $dst32, ",", register_map!("scratch", 32), "\n",
        $epilog,

        // JNE64_IMM
        util!("decode_imm", register_map!("scratch", 64)),
        util!("conditional_branch", $dst64, register_map!("scratch", 64), "cmp", "ne"),
        $epilog,

        // JNE32_IMM
        util!("decode_imm", register_map!("scratch", 64)),
        util!("conditional_branch", $dst32, register_map!("scratch", 32), "cmp", "ne"),
        $epilog,

        // AND64_IMM
        util!("decode_imm", register_map!("scratch", 64)),
        "and ", $dst64, ",", register_map!("scratch", 64), "\n",
        $epilog,

        util!("4_opcodes_invalid"),

        // AND32_REG
        "and ", $dst32, ", ", $src32, "\n",
        $epilog,

        // JNE64_REG
        util!("conditional_branch", $dst64, $src64, "cmp", "ne"),
        $epilog,

        // JNE32_REG
        util!("conditional_branch", $dst32, $src32, "cmp", "ne"),
        $epilog,

        // AND64_REG
        "and ", $dst64, ", ", $src64, "\n",
        $epilog,

        // Opcodes 0x60
        util!("1_opcode_invalid"),

        // LD_W_REG
        util!("1_opcode_invalid"),

        // ST_W_IMM
        util!("1_opcode_invalid"),

        // ST_W_REG
        util!("1_opcode_invalid"),

        // LSH32_IMM
        util!("decode_imm", register_map!("scratch", 64)),
        util!("bitshift", $dst32, register_map!("scratch", 64), register_map!("scratch", 32), "shl"),
        $epilog,

        // JSGT64_IMM
        util!("decode_imm", register_map!("scratch", 64)),
        util!("conditional_branch", $dst64, register_map!("scratch", 64), "cmp", "g"),
        $epilog,

        // JSGT32_IMM
        util!("decode_imm", register_map!("scratch", 64)),
        util!("conditional_branch", $dst32, register_map!("scratch", 32), "cmp", "g"),
        $epilog,

        // LSH64_IMM
        util!("decode_imm", register_map!("scratch", 64)),
        util!("bitshift", $dst64, register_map!("scratch", 64), register_map!("scratch", 64), "shl"),
        $epilog,

        util!("1_opcode_invalid"),

        // LD_H_REG
        util!("1_opcode_invalid"),

        // ST_H_IMM
        util!("1_opcode_invalid"),

        // ST_H_REG
        util!("1_opcode_invalid"),

        // LSH32_REG
        util!("bitshift", $dst32, $src64, register_map!("scratch", 32), "shl"),
        $epilog,

        // JSGT64_REG
        util!("conditional_branch", $dst64, $src64, "cmp", "g"),
        $epilog,

        // JSGT32_REG
        util!("conditional_branch", $dst32, $src32, "cmp", "g"),
        $epilog,

        // LSH64_REG
        util!("bitshift", $dst64, $src64, register_map!("scratch", 64), "shl"),
        $epilog,

        // Opcodes 0x70
        util!("1_opcode_invalid"),

        // LD_B_REG
        util!("1_opcode_invalid"),

        // ST_B_IMM
        util!("1_opcode_invalid"),

        // ST_B_REG
        util!("1_opcode_invalid"),

        // RSH32_IMM
        util!("decode_imm", register_map!("scratch", 64)),
        util!("bitshift", $dst32, register_map!("scratch", 64), register_map!("scratch", 32), "shr"),
        $epilog,

        // JSGE64_IMM
        util!("decode_imm", register_map!("scratch", 64)),
        util!("conditional_branch", $dst64, register_map!("scratch", 64), "cmp", "ge"),
        $epilog,

        // JSGE32_IMM
        util!("decode_imm", register_map!("scratch", 64)),
        util!("conditional_branch", $dst32, register_map!("scratch", 32), "cmp", "ge"),
        $epilog,

        // RSH64_IMM
        util!("decode_imm", register_map!("scratch", 64)),
        util!("bitshift", $dst64, register_map!("scratch", 64), register_map!("scratch", 64), "shr"),
        $epilog,

        util!("1_opcode_invalid"),

        // LD_DW_REG
        util!("1_opcode_invalid"),

        // ST_DW_IMM
        util!("1_opcode_invalid"),

        // ST_DW_REG
        util!("1_opcode_invalid"),

        // RSH32_REG
        util!("bitshift", $dst32, $src64, register_map!("scratch", 32), "shr"),
        $epilog,

        // JSGE64_REG
        util!("conditional_branch", $dst64, $src64, "cmp", "ge"),
        $epilog,

        // JSGE32_REG
        util!("conditional_branch", $dst32, $src32, "cmp", "ge"),
        $epilog,

        // RSH64_REG
        util!("bitshift", $dst64, $src64, register_map!("scratch", 64), "shr"),
        $epilog,

        // Opcodes 0x80
        util!("4_opcodes_invalid"),

        // NEG32
        "neg ", $dst32, "\n",
        $epilog,

        // CALL_IMM
        util!("verify_insn_limit", register_map!("insn_ptr", 64)),
        util!("1_opcode_invalid"),

        util!("1_opcode_invalid"),

        // NEG64
        "neg ", $dst64, "\n",
        $epilog,

        util!("4_opcodes_invalid"),

        util!("1_opcode_invalid"),

        // CALL_REG
        util!("verify_insn_limit", register_map!("insn_ptr", 64)),
        util!("1_opcode_invalid"),

        util!("1_opcode_invalid"),
        util!("1_opcode_invalid"),

        // Opcodes 0x90
        util!("4_opcodes_invalid"),

        // MOD32_IMM
        util!("decode_imm", register_map!("scratch", 64)),
        util!("verify_divisor", register_map!("scratch", 64)),
        util!("division", $dst32, register_map!("scratch", 32), register_map!("scratch", 32), "eax", "edx"),
        $epilog,

        // EXIT
        util!("verify_insn_limit", register_map!("insn_ptr", 64)),
        "ret\n",
        $epilog,

        util!("1_opcode_invalid"),

        // MOD64_IMM
        util!("decode_imm", register_map!("scratch", 64)),
        util!("verify_divisor", register_map!("scratch", 64)),
        util!("division", $dst64, register_map!("scratch", 64), register_map!("scratch", 64), "rax", "rdx"),
        $epilog,

        util!("4_opcodes_invalid"),

        // MOD32_REG
        util!("division", $dst32, $src32, register_map!("scratch", 32), "eax", "edx"),
        $epilog,

        util!("1_opcode_invalid"),
        util!("1_opcode_invalid"),

        // MOD64_REG
        util!("division", $dst64, $src64, register_map!("scratch", 64), "rax", "rdx"),
        $epilog,

        // Opcodes 0xA0
        util!("4_opcodes_invalid"),

        // XOR32_IMM
        util!("decode_imm", register_map!("scratch", 64)),
        "xor ", $dst32, ",", register_map!("scratch", 32), "\n",
        $epilog,

        // JLT64_IMM
        util!("decode_imm", register_map!("scratch", 64)),
        util!("conditional_branch", $dst64, register_map!("scratch", 64), "cmp", "b"),
        $epilog,

        // JLT32_IMM
        util!("decode_imm", register_map!("scratch", 64)),
        util!("conditional_branch", $dst32, register_map!("scratch", 32), "cmp", "b"),
        $epilog,

        // XOR64_IMM
        util!("decode_imm", register_map!("scratch", 64)),
        "xor ", $dst64, ",", register_map!("scratch", 64), "\n",
        $epilog,

        util!("4_opcodes_invalid"),

        // XOR32_REG
        "xor ", $dst32, ", ", $src32, "\n",
        $epilog,

        // JLT64_REG
        util!("conditional_branch", $dst64, $src64, "cmp", "b"),
        $epilog,

        // JLT32_REG
        util!("conditional_branch", $dst32, $src32, "cmp", "b"),
        $epilog,

        // XOR64_REG
        "xor ", $dst64, ", ", $src64, "\n",
        $epilog,

        // Opcodes 0xB0
        util!("4_opcodes_invalid"),

        // MOV32_IMM
        util!("decode_imm", register_map!("scratch", 64)),
        "mov ", $dst32, ",", register_map!("scratch", 32), "\n",
        $epilog,

        // JLE64_IMM
        util!("decode_imm", register_map!("scratch", 64)),
        util!("conditional_branch", $dst64, register_map!("scratch", 64), "cmp", "be"),
        $epilog,

        // JLE32_IMM
        util!("decode_imm", register_map!("scratch", 64)),
        util!("conditional_branch", $dst32, register_map!("scratch", 32), "cmp", "be"),
        $epilog,

        // MOV64_IMM
        util!("decode_imm", register_map!("scratch", 64)),
        "mov ", $dst64, ",", register_map!("scratch", 64), "\n",
        $epilog,

        util!("4_opcodes_invalid"),

        // MOV32_REG
        "mov ", $dst32, ", ", $src32, "\n",
        $epilog,

        // JLE64_REG
        util!("conditional_branch", $dst64, $src64, "cmp", "be"),
        $epilog,

        // JLE32_REG
        util!("conditional_branch", $dst32, $src32, "cmp", "be"),
        $epilog,

        // MOV64_REG
        "mov ", $dst64, ", ", $src64, "\n",
        $epilog,

        // Opcodes 0xC0
        util!("4_opcodes_invalid"),

        // ARSH32_IMM
        util!("decode_imm", register_map!("scratch", 64)),
        util!("bitshift", $dst32, register_map!("scratch", 64), register_map!("scratch", 32), "sar"),
        $epilog,

        // JSLT64_IMM
        util!("decode_imm", register_map!("scratch", 64)),
        util!("conditional_branch", $dst64, register_map!("scratch", 64), "cmp", "l"),
        $epilog,

        // JSLT32_IMM
        util!("decode_imm", register_map!("scratch", 64)),
        util!("conditional_branch", $dst32, register_map!("scratch", 32), "cmp", "l"),
        $epilog,

        // ARSH64_IMM
        util!("decode_imm", register_map!("scratch", 64)),
        util!("bitshift", $dst64, register_map!("scratch", 64), register_map!("scratch", 64), "sar"),
        $epilog,

        util!("4_opcodes_invalid"),

        // ARSH32_REG
        util!("bitshift", $dst32, $src64, register_map!("scratch", 32), "sar"),
        $epilog,

        // JSLT64_REG
        util!("conditional_branch", $dst64, $src64, "cmp", "l"),
        $epilog,

        // JSLT32_REG
        util!("conditional_branch", $dst32, $src32, "cmp", "l"),
        $epilog,

        // ARSH64_REG
        util!("bitshift", $dst64, $src64, register_map!("scratch", 64), "sar"),
        $epilog,

        // Opcodes 0xD0
        util!("4_opcodes_invalid"),

        // LE
        util!("decode_imm", register_map!("scratch", 64)),
        "mov ", register_map!("scratch", 64), ", ", $dst64, "\n",
        "call subroutine_le\n",
        "mov ", $dst64, ", ", register_map!("scratch", 64), "\n",
        $epilog,

        // JSLE64_IMM
        util!("decode_imm", register_map!("scratch", 64)),
        util!("conditional_branch", $dst64, register_map!("scratch", 64), "cmp", "le"),
        $epilog,

        // JSLE32_IMM
        util!("decode_imm", register_map!("scratch", 64)),
        util!("conditional_branch", $dst32, register_map!("scratch", 32), "cmp", "le"),
        $epilog,

        util!("1_opcode_invalid"),
        util!("4_opcodes_invalid"),

        // BE
        util!("decode_imm", register_map!("scratch", 64)),
        "mov ", register_map!("scratch", 64), ", ", $dst64, "\n",
        "call subroutine_be\n",
        "mov ", $dst64, ", ", register_map!("scratch", 64), "\n",
        $epilog,

        // JSLT64_REG
        util!("conditional_branch", $dst64, $src64, "cmp", "le"),
        $epilog,

        // JSLT32_REG
        util!("conditional_branch", $dst32, $src32, "cmp", "le"),
        $epilog,

        util!("1_opcode_invalid"),

        // Opcodes 0xE0
        util!("16_opcodes_invalid"),

        // Opcodes 0xF0
        util!("16_opcodes_invalid"),
    ));
}

macro_rules! util {
    ("decode_opcode", $target:expr) => (concat!(
        "movzx ", $target, ", word ptr [", register_map!("insn_ptr", 64), "]\n",
        "shl ", $target, ", 6\n",
        // "add ", $target, ", gs:0\n",
        "lea rbp, [rip + gadgets]\n",
        "add ", $target, ", rbp\n",
    ));
    ("decode_offset", $dst64:expr) => (concat!(
        "movsx ", $dst64, ", word ptr [", register_map!("insn_ptr", 64), " + 2]\n"
    ));
    ("decode_imm", $dst64:expr) => (concat!(
        "movsxd ", $dst64, ", dword ptr [", register_map!("insn_ptr", 64), " + 4]\n"
    ));
    ("verify_divisor", $dst:expr) => (concat!(
        "cmp ", $dst, ", 0\n",
        "je divide_by_zero\n",
    ));
    ("verify_insn_limit", $insn_ptr:expr) => (concat!(
        "cmp ", $insn_ptr, ", ", register_map!("insn_limit", 64), "\n",
        "jge exceeded_max_instructions\n",
    ));
    ("slot_in_vm", $slot_offset:expr) => (concat!(
        "qword ptr gs:[", $slot_offset, "]"
    ));
    ("error_handler", $err:literal) => (concat!(
        $err, ":",
        "mov ", util!("slot_in_vm", "{vm_slot_program_result} + 0x00"), ", {program_result_err}\n",
        "mov ", util!("slot_in_vm", "{vm_slot_program_result} + 0x08"), ", {", $err, "}\n",
        "mov rsp, ", util!("slot_in_vm", "{vm_slot_host_stack_pointer}"), "\n",
        "jmp interpreter_exitpoint\n",
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
    ("bitshift", $dst:expr, $src64:expr, $scratch:expr, $shift_type:expr) => (concat!(
        "push rcx\n",
        "mov rcx, ", $src64, "\n",
        "mov ", $scratch, ", ", $dst, "\n",
        $shift_type, " ", $scratch, ", cl\n",
        "pop rcx\n",
        "mov ", $dst, ", ", $scratch, "\n",
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
        util!("1_opcode_invalid"),
        util!("1_opcode_invalid"),
        util!("1_opcode_invalid"),
        util!("1_opcode_invalid"),
        util!("1_opcode_invalid"),
        util!("1_opcode_invalid"),
        util!("1_opcode_invalid"),
        util!("1_opcode_invalid"),
        util!("1_opcode_invalid"),
        util!("1_opcode_invalid"),
        util!("1_opcode_invalid"),
        util!("1_opcode_invalid"),
        util!("1_opcode_invalid"),
        util!("1_opcode_invalid"),
        util!("1_opcode_invalid"),
        util!("1_opcode_invalid"),
    ));
    ("256_opcodes_invalid") => (concat!(
        util!("16_opcodes_invalid"),
        util!("16_opcodes_invalid"),
        util!("16_opcodes_invalid"),
        util!("16_opcodes_invalid"),
        util!("16_opcodes_invalid"),
        util!("16_opcodes_invalid"),
        util!("16_opcodes_invalid"),
        util!("16_opcodes_invalid"),
        util!("16_opcodes_invalid"),
        util!("16_opcodes_invalid"),
        util!("16_opcodes_invalid"),
        util!("16_opcodes_invalid"),
        util!("16_opcodes_invalid"),
        util!("16_opcodes_invalid"),
        util!("16_opcodes_invalid"),
        util!("16_opcodes_invalid"),
    ));
    ("4096_opcodes_invalid") => (concat!(
        util!("256_opcodes_invalid"),
        util!("256_opcodes_invalid"),
        util!("256_opcodes_invalid"),
        util!("256_opcodes_invalid"),
        util!("256_opcodes_invalid"),
        util!("256_opcodes_invalid"),
        util!("256_opcodes_invalid"),
        util!("256_opcodes_invalid"),
        util!("256_opcodes_invalid"),
        util!("256_opcodes_invalid"),
        util!("256_opcodes_invalid"),
        util!("256_opcodes_invalid"),
        util!("256_opcodes_invalid"),
        util!("256_opcodes_invalid"),
        util!("256_opcodes_invalid"),
        util!("256_opcodes_invalid"),
    ));
}

macro_rules! register_map {
    ("r0", 16) => ("ax"); ("r0", 32) => ("eax"); ("r0", 64) => ("rax");
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
    ("insn_ptr", 16) => ("di"); ("insn_ptr", 32) => ("edi"); ("insn_ptr", 64) => ("rdi");
    ("insn_limit", 16) => ("r10w"); ("insn_limit", 32) => ("r10d"); ("insn_limit", 64) => ("r10");
    ("scratch", 16) => ("r11w"); ("scratch", 32) => ("r11d"); ("scratch", 64) => ("r11");
}

macro_rules! all_src_and_dst_regs_and_opcodes {
    ($epilog:expr, $src32:expr, $src64:expr) => (concat!(
        all_opcodes!($epilog, register_map!("r0", 32), register_map!("r0", 64), $src32, $src64),
        all_opcodes!($epilog, register_map!("r1", 32), register_map!("r1", 64), $src32, $src64),
        all_opcodes!($epilog, register_map!("r2", 32), register_map!("r2", 64), $src32, $src64),
        all_opcodes!($epilog, register_map!("r3", 32), register_map!("r3", 64), $src32, $src64),
        all_opcodes!($epilog, register_map!("r4", 32), register_map!("r4", 64), $src32, $src64),
        all_opcodes!($epilog, register_map!("r5", 32), register_map!("r5", 64), $src32, $src64),
        all_opcodes!($epilog, register_map!("r6", 32), register_map!("r6", 64), $src32, $src64),
        all_opcodes!($epilog, register_map!("r7", 32), register_map!("r7", 64), $src32, $src64),
        all_opcodes!($epilog, register_map!("r8", 32), register_map!("r8", 64), $src32, $src64),
        all_opcodes!($epilog, register_map!("r9", 32), register_map!("r9", 64), $src32, $src64),
        all_opcodes!($epilog, register_map!("r10", 32), register_map!("r10", 64), $src32, $src64),
        util!("256_opcodes_invalid"),
        util!("256_opcodes_invalid"),
        util!("256_opcodes_invalid"),
        util!("256_opcodes_invalid"),
        util!("256_opcodes_invalid"),
    ));
    ($epilog:expr) => (concat!(
        all_src_and_dst_regs_and_opcodes!($epilog, register_map!("r0", 32), register_map!("r0", 64)),
        all_src_and_dst_regs_and_opcodes!($epilog, register_map!("r1", 32), register_map!("r1", 64)),
        all_src_and_dst_regs_and_opcodes!($epilog, register_map!("r2", 32), register_map!("r2", 64)),
        all_src_and_dst_regs_and_opcodes!($epilog, register_map!("r3", 32), register_map!("r3", 64)),
        all_src_and_dst_regs_and_opcodes!($epilog, register_map!("r4", 32), register_map!("r4", 64)),
        all_src_and_dst_regs_and_opcodes!($epilog, register_map!("r5", 32), register_map!("r5", 64)),
        all_src_and_dst_regs_and_opcodes!($epilog, register_map!("r6", 32), register_map!("r6", 64)),
        all_src_and_dst_regs_and_opcodes!($epilog, register_map!("r7", 32), register_map!("r7", 64)),
        all_src_and_dst_regs_and_opcodes!($epilog, register_map!("r8", 32), register_map!("r8", 64)),
        all_src_and_dst_regs_and_opcodes!($epilog, register_map!("r9", 32), register_map!("r9", 64)),
        all_src_and_dst_regs_and_opcodes!($epilog, register_map!("r10", 32), register_map!("r10", 64)),
        util!("4096_opcodes_invalid"),
        util!("4096_opcodes_invalid"),
        util!("4096_opcodes_invalid"),
        util!("4096_opcodes_invalid"),
        util!("4096_opcodes_invalid"),
    ));
}

#[cfg(test)]
const _: &str = all_src_and_dst_regs_and_opcodes!("ret\n");

#[cfg(not(test))]
use crate::{error::{EbpfError, ProgramResult}, vm::RuntimeEnvironmentSlot};

#[cfg(not(test))]
std::arch::global_asm!(concat!(
    ".global gadgets
    gadgets:\n",
    all_src_and_dst_regs_and_opcodes!(concat!(
        "add ", register_map!("insn_ptr", 64), ", 8\n",
        util!("decode_opcode", register_map!("scratch", 64)),
        "jmp ", register_map!("scratch", 64), "\n",
        ".align 64\n",
    )),

    util!("error_handler", "exceeded_max_instructions"),
    util!("error_handler", "call_depth_exeeded"),
    util!("error_handler", "call_outside_text_segment"),
    util!("error_handler", "divide_by_zero"),
    util!("error_handler", "divide_overflow"),
    util!("error_handler", "unsupported_instruction"),

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

    // ".byte 0x49\n.byte 0x81\n.byte 0xC3\n.long [gadgets - .]\n", // "add r11, gadgets - .\n"
    // .intel_syntax
    // .att_syntax

    ".global interpreter_entrypoint\n",
    "interpreter_entrypoint:\n",
    "push rbx\n",
    "push rbp\n",
    "push r12\n",
    "push r13\n",
    "push r14\n",
    "push r15\n",
    "wrgsbase rdi\n",
    // "lea ", register_map!("scratch", 64), ", [rip + gadgets]\n",
    // "mov ", util!("slot_in_vm", "{vm_slot_gadgets_base_pointer}"), ", ", register_map!("scratch", 64), "\n",
    "mov ", util!("slot_in_vm", "{vm_slot_host_stack_pointer}"), ", rsp\n",
    "mov ", register_map!("insn_ptr", 64), ", ", util!("slot_in_vm", "{vm_slot_registers} + 0x58"), "\n",
    "shl ", register_map!("insn_ptr", 64), ", 3\n",
    "add ", register_map!("insn_ptr", 64), ", rsi\n",
    "push rsi\n",
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
    util!("decode_opcode", register_map!("scratch", 64)),
    "call ", register_map!("scratch", 64), "\n",
    "mov ", util!("slot_in_vm", "{vm_slot_program_result} + 0x00"), ", {program_result_ok}\n",
    "mov ", util!("slot_in_vm", "{vm_slot_program_result} + 0x08"), ", ", register_map!("r0", 64), "\n",
    "sub ", register_map!("insn_limit", 64), ", ", register_map!("insn_ptr", 64), "\n",
    "shr ", register_map!("insn_limit", 64), ", 3\n",
    "mov ", register_map!("scratch", 64), ", ", util!("slot_in_vm", "{vm_slot_previous_instruction_meter}"), "\n",
    "sub ", register_map!("scratch", 64), ", ", register_map!("insn_limit", 64), "\n",
    "mov ", util!("slot_in_vm", "{vm_slot_due_insn_count}"), ", ", register_map!("scratch", 64), "\n",
    "pop rsi\n",
    "sub ", register_map!("insn_ptr", 64), ", rsi\n",
    "shr ", register_map!("insn_ptr", 64), ", 3\n",
    "mov ", util!("slot_in_vm", "{vm_slot_registers} + 0x58"), ", ", register_map!("insn_ptr", 64), "\n",
    "interpreter_exitpoint:\n",
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
    "pop r15\n",
    "pop r14\n",
    "pop r13\n",
    "pop r12\n",
    "pop rbp\n",
    "pop rbx\n",
    "ret\n"),

    vm_slot_host_stack_pointer = const RuntimeEnvironmentSlot::HostStackPointer as usize,
    // vm_slot_call_depth = const RuntimeEnvironmentSlot::CallDepth as usize,
    // vm_slot_context_object_pointer = const RuntimeEnvironmentSlot::ContextObjectPointer as usize,
    vm_slot_previous_instruction_meter = const RuntimeEnvironmentSlot::PreviousInstructionMeter as usize,
    vm_slot_due_insn_count = const RuntimeEnvironmentSlot::DueInsnCount as usize,
    // vm_slot_stopwatch_numerator = const RuntimeEnvironmentSlot::StopwatchNumerator as usize,
    // vm_slot_stopwatch_denominator = const RuntimeEnvironmentSlot::StopwatchDenominator as usize,
    vm_slot_registers = const RuntimeEnvironmentSlot::Registers as usize,
    vm_slot_program_result = const RuntimeEnvironmentSlot::ProgramResult as usize,
    // vm_slot_memory_mapping = const RuntimeEnvironmentSlot::MemoryMapping as usize,
    // vm_slot_register_trace = const RuntimeEnvironmentSlot::RegisterTrace as usize,

    program_result_ok = const ProgramResult::Ok(0).discriminant(),
    program_result_err = const ProgramResult::Err(EbpfError::UnsupportedInstruction).discriminant(),
    exceeded_max_instructions = const EbpfError::ExceededMaxInstructions.discriminant(),
    call_depth_exeeded = const EbpfError::CallDepthExceeded.discriminant(),
    call_outside_text_segment = const EbpfError::CallOutsideTextSegment.discriminant(),
    divide_by_zero = const EbpfError::DivideByZero.discriminant(),
    divide_overflow = const EbpfError::DivideOverflow.discriminant(),
    unsupported_instruction = const EbpfError::UnsupportedInstruction.discriminant(),
);

#[allow(dead_code)]
unsafe extern "C" {
    fn gadgets();
    fn interpreter_entrypoint(vm: *mut (), program: *const u64);
}

#[cfg(test)]
mod tests {
    use crate::{
        assembler::assemble,
        elf::Executable,
        interpreter::Interpreter,
        memory_region::MemoryMapping,
        program::BuiltinProgram,
        program::SBPFVersion,
        vm::{CallFrame, Config, ContextObject, EbpfVm},
    };
    // use test_utils::TestContextObject;
    use std::{ptr, sync::Arc};
    extern crate test;
    use test::Bencher;

    const INTERPRETER: unsafe extern "C" fn(*mut EbpfVm<TestContextObject>, *const u64) = unsafe { std::mem::transmute(super::interpreter_entrypoint as unsafe extern "C" fn(*mut (), *const u64)) };

    fn setup_program_and_vm<'a>(context_object: &'a mut TestContextObject, sbpf_asm: &str) -> (Executable<TestContextObject>, *const u64, EbpfVm::<'a, TestContextObject>) {
        let config = Config::default();
        let loader = Arc::new(BuiltinProgram::new_loader(config));
        let executable = assemble::<TestContextObject>(sbpf_asm, Arc::clone(&loader)).unwrap();
        let program = executable.get_text_bytes().1.as_ptr().cast::<u64>();
        let mut vm = EbpfVm::<TestContextObject>::new(
            loader,
            SBPFVersion::V3,
            context_object,
            0x1000,
        );
        vm.previous_instruction_meter = 100000000;
        vm.due_insn_count = 0;
        vm.registers[11] = executable.get_entrypoint_instruction_offset() as u64;
        (executable, program, vm)
    }

    /// Simple instruction meter for testing
    #[derive(Debug)]
    pub struct TestContextObject {
        /// Maximal amount of instructions which still can be executed
        pub remaining: u64,
        pub memory_mapping: MemoryMapping,
    }

    impl Default for TestContextObject {
        fn default() -> Self {
            Self {
                remaining: 0,
                memory_mapping: unsafe {
                    MemoryMapping::new(vec![], &Config::default(), SBPFVersion::Reserved)
                }
                .unwrap(),
            }
        }
    }

    impl ContextObject for TestContextObject {
        fn consume(&mut self, amount: u64) {
            self.remaining = self.remaining.saturating_sub(amount);
        }

        fn get_remaining(&self) -> u64 {
            self.remaining
        }

        fn active_mapping_ptr(&mut self) -> ptr::NonNull<MemoryMapping> {
            ptr::NonNull::from_ref(&mut self.memory_mapping)
        }
    }

    #[test]
    fn print_out_gadgets() {
        const PTR: unsafe extern "C" fn() = super::gadgets as unsafe extern "C" fn();
        println!("PTR: {:?}", PTR);
        let slice = unsafe { std::slice::from_raw_parts(PTR as *const u8, 64 * 8 * 8) };
        for i in 0..64 {
            println!("{:02}: {:02X?}", i, &slice[i * 64..(i + 1) * 64]);
        }
    }

    #[test]
    fn run_interpreter() {
        let mut context_object = TestContextObject::default();
        let (executable, program, mut vm) = setup_program_and_vm(&mut context_object, "
            lddw r1, 0x1122334455667788
            be16 r1
            lddw r2, 0x1122334455667788
            be32 r2
            lddw r3, 0x1122334455667788
            be64 r3
        continue:
            jgt r0, 3, break
            add r0, 1
            ja continue
        break:
            exit
        ");

        unsafe { INTERPRETER(&mut vm, program); }
        println!("program_result: {:?}", vm.program_result);
        println!("consumed instructions: {}", vm.due_insn_count);
        println!("registers: {:016X?}", vm.registers);
        drop(executable);
    }

    const BENCH_ASM: &str = "
        mov r1, r2
        and r1, 1023
        add r2, 1
        jlt r2, 0x200000, -4
        exit
    ";

    #[bench]
    fn old_interpreter(b: &mut Bencher) {
        let mut context_object = TestContextObject::default();
        let (executable, _program, mut vm) = setup_program_and_vm(&mut context_object, BENCH_ASM);
        let mut call_frames = vec![CallFrame::default(); 64];
        let mut interpreter = Interpreter::new(&mut vm, &executable, [0; 12], &mut call_frames);
        b.iter(|| {
            interpreter.reg[2] = 0;
            interpreter.reg[11] = executable.get_entrypoint_instruction_offset() as u64;
            interpreter.vm.previous_instruction_meter = 100000000;
            interpreter.vm.due_insn_count = 0;
            test::black_box(while interpreter.step() {});
        });
        drop(executable);
    }

    #[bench]
    fn new_interpreter(b: &mut Bencher) {
        let mut context_object = TestContextObject::default();
        let (executable, program, mut vm) = setup_program_and_vm(&mut context_object, BENCH_ASM);
        b.iter(|| {
            vm.registers[2] = 0;
            vm.registers[11] = executable.get_entrypoint_instruction_offset() as u64;
            vm.previous_instruction_meter = 100000000;
            vm.due_insn_count = 0;
            test::black_box(unsafe { INTERPRETER(&mut vm, program); });
        });
        drop(executable);
    }
}

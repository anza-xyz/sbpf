//! Looks at the machine code of `codegen`, and runs programs with it.
//!
//! `<program>` is either an ELF (the file name ends with `.so`) or assembly text.
//!
//! Needs the `codegen-debug` feature. With it, on Linux and with `SBPF_DEBUG_CODE_DIR` set, the
//! generated code is itself in ELF files (`sbpf-<pid>-<label>.elf` there), which the profilers and
//! debuggers running the tool read the symbols of: see `run --maps`, and `codegen::debug`.

#[cfg(target_arch = "x86_64")]
mod tool {
    use clap::{Args, Parser, Subcommand, ValueEnum};
    use solana_sbpf::{
        assembler::assemble,
        codegen::debug,
        ebpf,
        elf::Executable,
        memory_region::MemoryRegion,
        program::{BuiltinFunctionDefinition, BuiltinProgram, SBPFVersion},
        verifier::RequisiteVerifier,
        vm::{CallFrame, Config, ExecutionMode},
    };
    use std::{path::PathBuf, process::Command, sync::Arc};
    use test_utils::{create_vm, syscalls, TestContextObject};

    /// Looks at the machine code of `codegen`, and runs programs with it.
    #[derive(Parser)]
    struct Cli {
        #[command(subcommand)]
        action: Action,
    }

    #[derive(Subcommand)]
    enum Action {
        Elf(ElfArgs),
        Template(TemplateArgs),
        Run(RunArgs),
    }

    /// The SBPF versions that `codegen` supports.
    #[derive(Clone, Copy, ValueEnum)]
    enum Version {
        V0,
        V3,
        V4,
    }

    impl Version {
        fn sbpf(self) -> SBPFVersion {
            match self {
                Version::V0 => SBPFVersion::V0,
                Version::V3 => SBPFVersion::V3,
                Version::V4 => SBPFVersion::V4,
            }
        }
    }

    /// Bytes given in hexadecimal, which may be separated by spaces or commas.
    #[derive(Clone)]
    struct HexBytes(Vec<u8>);

    /// Write the supporting code, and optionally the interpreter and the JIT output of a program,
    /// into an ELF file, for objdump, nm and gdb.
    #[derive(Args)]
    struct ElfArgs {
        /// The SBPF version to generate the code for.
        #[arg(long, value_enum)]
        version: Version,
        /// The ELF file to write.
        #[arg(short, long)]
        out: PathBuf,
        /// Include the interpreter.
        #[arg(long)]
        interpreter: bool,
        /// Include the JIT output of this program.
        #[arg(long, value_name = "PROGRAM")]
        jit: Option<String>,
    }

    /// Show the JIT template of an instruction.
    ///
    /// The instruction is given as 16 bits: the opcode in bits 0 to 7, the destination register in
    /// bits 8 to 11 and the source register in bits 12 to 15, in hex with the 0x prefix (e.g.
    /// 0x1207 is `add64 r2, imm` with the source field set to 1), or as assembly, such as
    /// "add64 r2, 5".
    #[derive(Args)]
    struct TemplateArgs {
        /// The SBPF version to generate the code for.
        #[arg(long, value_enum)]
        version: Version,
        /// The instruction.
        #[arg(required = true, num_args = 1.., allow_hyphen_values = true)]
        instruction: Vec<String>,
    }

    /// Run a program with the interpreter and the JIT (unless one is chosen), and compare them.
    ///
    /// The input is placed at the start of the input region, and r1 points at it.
    #[derive(Args)]
    struct RunArgs {
        /// The SBPF version to run the program as.
        #[arg(long, value_enum)]
        version: Version,
        /// Only run the interpreter.
        #[arg(long, conflicts_with = "jit")]
        interpreter: bool,
        /// Only run the JIT.
        #[arg(long)]
        jit: bool,
        /// The instruction budget.
        #[arg(long, default_value_t = 1_000_000)]
        budget: u64,
        /// The input, in hex.
        #[arg(long, value_parser = parse_hex, value_name = "HEX")]
        input: Option<HexBytes>,
        /// Print the memory mappings of the generated code, which are of the ELF files of this
        /// process, so that the tools know their symbols.
        #[arg(long)]
        maps: bool,
        /// An ELF (the file name ends with `.so`), or assembly text.
        program: String,
    }

    fn die(message: String) -> ! {
        eprintln!("error: {message}");
        std::process::exit(1);
    }

    fn parse_hex(text: &str) -> Result<HexBytes, String> {
        let digits: Vec<u8> = text
            .trim_start_matches("0x")
            .bytes()
            .filter(|byte| !byte.is_ascii_whitespace() && *byte != b',')
            .collect();
        if !digits.len().is_multiple_of(2) {
            return Err("an odd number of hex digits".to_string());
        }
        let mut bytes = Vec::new();
        for pair in digits.chunks(2) {
            let pair = std::str::from_utf8(pair).unwrap_or("");
            bytes.push(u8::from_str_radix(pair, 16).map_err(|_| "not hex".to_string())?);
        }
        Ok(HexBytes(bytes))
    }

    /// The loader for programs of `version`, with the syscalls of the tests.
    fn loader(version: SBPFVersion) -> Arc<BuiltinProgram<TestContextObject>> {
        let config = Config {
            enabled_sbpf_versions: version..=version,
            // The output is the same on every run.
            noop_instruction_rate: 0,
            ..Config::default()
        };
        let mut loader = BuiltinProgram::new_loader(config);
        syscalls::SyscallString::register(&mut loader, "log").unwrap();
        syscalls::SyscallString::register(&mut loader, "bpf_syscall_string").unwrap();
        syscalls::SyscallU64::register(&mut loader, "bpf_syscall_u64").unwrap();
        syscalls::SyscallTracePrintf::register(&mut loader, "bpf_trace_printf").unwrap();
        syscalls::SyscallGatherBytes::register(&mut loader, "bpf_gather_bytes").unwrap();
        syscalls::SyscallMemFrob::register(&mut loader, "bpf_mem_frob").unwrap();
        syscalls::SyscallStrCmp::register(&mut loader, "bpf_str_cmp").unwrap();
        Arc::new(loader)
    }

    fn load(path: &str, version: SBPFVersion) -> Executable<TestContextObject> {
        let loader = loader(version);
        let executable = if path.ends_with(".so") {
            let elf = std::fs::read(path).unwrap_or_else(|e| die(format!("{path}: {e}")));
            Executable::from_elf(&elf, loader).map_err(|e| format!("{e:?}"))
        } else {
            let text =
                std::fs::read_to_string(path).unwrap_or_else(|e| die(format!("{path}: {e}")));
            assemble(&text, loader)
        }
        .unwrap_or_else(|e| die(format!("{path}: {e}")));
        executable
            .verify::<RequisiteVerifier>()
            .unwrap_or_else(|e| die(format!("{path}: {e:?}")));
        executable
    }

    fn dynasm_compile(executable: &Executable<TestContextObject>) {
        executable
            .dynasm_compile()
            .unwrap_or_else(|e| die(format!("failed to compile: {e:?}")));
    }

    fn elf(args: ElfArgs) {
        let version = args.version.sbpf();
        let mut regions = vec![debug::supporting_code()];
        if args.interpreter {
            regions.push(debug::interpreter(version));
        }
        if let Some(path) = &args.jit {
            let executable = load(path, version);
            dynasm_compile(&executable);
            let program = executable.get_compiled_program().unwrap();
            regions.push(debug::jit(&executable, &program));
        }
        debug::write_elf(&args.out, &regions)
            .unwrap_or_else(|e| die(format!("{}: {e}", args.out.display())));
        for region in &regions {
            println!(
                "{}: {:#x}..{:#x}, {} symbols",
                region.name,
                region.start,
                region.start.wrapping_add(region.bytes.len()),
                region.symbols.len()
            );
        }
    }

    fn template(args: TemplateArgs) {
        let version = args.version.sbpf();
        let rest = args.instruction.join(" ");
        let hex = rest.trim().strip_prefix("0x");
        let opcode = match hex.map(|hex| u16::from_str_radix(hex, 16)) {
            Some(Ok(opcode)) => opcode,
            Some(Err(_)) => die(format!("{rest:?} is not a 16 bit hex number")),
            None => {
                let executable =
                    assemble::<TestContextObject>(&format!("{rest}\n"), loader(version))
                        .unwrap_or_else(|e| {
                            die(format!("{rest:?} is neither hex nor assembly: {e}"))
                        });
                let first = executable.get_text_bytes().1.first_chunk::<8>().copied();
                let first = first.unwrap_or_else(|| die("no instruction".to_string()));
                u64::from_le_bytes(first) as u16
            }
        };
        let template = debug::template(version, opcode);
        println!(
            "opcode {opcode:#06x}: op {:#04x}, dst r{}, src r{}",
            opcode & 0xff,
            (opcode >> 8) & 0xf,
            opcode >> 12
        );
        let hex: Vec<String> = template.code.iter().map(|b| format!("{b:02x}")).collect();
        println!("{} bytes: {}", template.code.len(), hex.join(" "));
        for relocation in &template.relocations {
            println!("relocation: {relocation}");
        }
        let file = std::env::temp_dir().join(format!("dynasm-template-{}.bin", std::process::id()));
        std::fs::write(&file, &template.code).unwrap_or_else(|e| die(format!("{file:?}: {e}")));
        let output = Command::new("objdump")
            .args(["-D", "-b", "binary", "-m", "i386:x86-64", "-M", "intel"])
            .arg(&file)
            .output();
        let _ = std::fs::remove_file(&file);
        match output {
            Ok(output) => print!("{}", String::from_utf8_lossy(&output.stdout)),
            Err(e) => println!("(no disassembly: objdump: {e})"),
        }
    }

    struct Outcome {
        result: String,
        instruction_count: u64,
        registers: [u64; 12],
        input: Vec<u8>,
    }

    fn execute(
        executable: &Executable<TestContextObject>,
        mut mode: ExecutionMode,
        budget: u64,
        input: &[u8],
    ) -> Outcome {
        let mut input = input.to_vec();
        let mut context_object = TestContextObject::new(budget);
        let region = MemoryRegion::new(&raw mut input[..], ebpf::MM_INPUT_START);
        create_vm!(
            vm,
            executable,
            &mut context_object,
            stack,
            heap,
            vec![region],
            None
        );
        // The interpreter of `codegen` needs no call frames, but the one of the crate does.
        let mut call_frames = vec![CallFrame::default(); executable.get_config().max_call_depth];
        let (instruction_count, result) =
            vm.execute_program(executable, &mut mode, &mut call_frames);
        let registers = vm.registers;
        drop(vm);
        Outcome {
            result: format!("{result:?}"),
            instruction_count,
            registers,
            input,
        }
    }

    fn report(name: &str, outcome: &Outcome) {
        println!("{name}: {}", outcome.result);
        println!("  instructions: {}", outcome.instruction_count);
        // `codegen` writes back the program counter (r11) and the result, but not the other registers.
        let registers: Vec<String> = outcome
            .registers
            .iter()
            .enumerate()
            .map(|(i, r)| format!("r{i}={r:#x}"))
            .collect();
        println!(
            "  registers as left in the vm (only r11, the pc, is written back): {}",
            registers.join(" ")
        );
    }

    fn run(args: RunArgs) {
        let version = args.version.sbpf();
        let input = args.input.map(|input| input.0).unwrap_or_default();
        let (interpreter, jit) = (!args.jit, !args.interpreter);
        let executable = load(&args.program, version);
        let mut outcomes = Vec::new();
        if interpreter {
            let outcome = execute(
                &executable,
                ExecutionMode::DynasmInterpreted,
                args.budget,
                &input,
            );
            report("interpreter", &outcome);
            outcomes.push(outcome);
        }
        if jit {
            dynasm_compile(&executable);
            let outcome = execute(&executable, ExecutionMode::Jit, args.budget, &input);
            report("jit", &outcome);
            outcomes.push(outcome);
        }
        if let [a, b] = outcomes.as_slice() {
            let agree = a.result == b.result
                && a.instruction_count == b.instruction_count
                && a.registers[11] == b.registers[11]
                && a.input == b.input;
            println!(
                "interpreter and jit {}",
                if agree { "agree" } else { "DIVERGE" }
            );
            if !agree {
                std::process::exit(1);
            }
        }
        if args.maps {
            // The code is generated into the files of this process.
            let prefix = format!("/sbpf-{}-", std::process::id());
            let maps = std::fs::read_to_string("/proc/self/maps").unwrap_or_default();
            for line in maps
                .lines()
                .filter(|line| line.contains(&prefix) && line.ends_with(".elf"))
            {
                println!("{line}");
            }
        }
    }

    pub fn main() {
        match Cli::parse().action {
            Action::Elf(args) => elf(args),
            Action::Template(args) => template(args),
            Action::Run(args) => run(args),
        }
    }
}

#[cfg(target_arch = "x86_64")]
fn main() {
    tool::main()
}

#[cfg(not(target_arch = "x86_64"))]
fn main() {}

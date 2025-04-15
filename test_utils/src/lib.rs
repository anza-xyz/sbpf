// Converted from the tests for uBPF <https://github.com/iovisor/ubpf>
// Copyright 2015 Big Switch Networks, Inc
// Copyright 2016 6WIND S.A. <quentin.monnet@6wind.com>
//
// Licensed under the Apache License, Version 2.0 <http://www.apache.org/licenses/LICENSE-2.0> or
// the MIT license <http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

#![allow(dead_code)]

use solana_sbpf::{
    aligned_memory::AlignedMemory,
    ebpf::{self, HOST_ALIGN},
    elf::Executable,
    error::EbpfError,
    memory_region::{MemoryCowCallback, MemoryMapping, MemoryRegion},
    static_analysis::TraceLogEntry,
    vm::ContextObject,
};

pub mod syscalls;

/// Simple instruction meter for testing
#[derive(Debug, Clone, Default)]
pub struct TestContextObject {
    /// Contains the register state at every instruction in order of execution
    pub trace_log: Vec<TraceLogEntry>,
    /// Maximal amount of instructions which still can be executed
    pub remaining: u64,
}

impl ContextObject for TestContextObject {
    fn trace(&mut self, state: [u64; 12]) {
        self.trace_log.push(state);
    }

    fn consume(&mut self, amount: u64) {
        self.remaining = self.remaining.saturating_sub(amount);
    }

    fn get_remaining(&self) -> u64 {
        self.remaining
    }
}

impl TestContextObject {
    /// Initialize with instruction meter
    pub fn new(remaining: u64) -> Self {
        Self {
            trace_log: Vec::new(),
            remaining,
        }
    }

    /// Compares an interpreter trace and a JIT trace.
    ///
    /// The log of the JIT can be longer because it only validates the instruction meter at branches.
    pub fn compare_trace_log(interpreter: &Self, jit: &Self) -> bool {
        let interpreter = interpreter.trace_log.as_slice();
        let mut jit = jit.trace_log.as_slice();
        if jit.len() > interpreter.len() {
            jit = &jit[0..interpreter.len()];
        }
        interpreter == jit
    }
}

// Assembly code and data for tcp_sack testcases.

pub const PROG_TCP_PORT_80: &str = "
    ldxb r2, [r1+0xc]
    ldxb r3, [r1+0xd]
    lsh64 r3, 0x8
    or64 r3, r2
    mov64 r0, 0x0
    jne r3, 0x8, +0xc
    ldxb r2, [r1+0x17]
    jne r2, 0x6, +0xa
    ldxb r2, [r1+0xe]
    add64 r1, 0xe
    and64 r2, 0xf
    lsh64 r2, 0x2
    add64 r1, r2
    ldxh r2, [r1+0x2]
    jeq r2, 0x5000, +0x2
    ldxh r1, [r1+0x0]
    jne r1, 0x5000, +0x1
    mov64 r0, 0x1
    exit";

pub const TCP_SACK_ASM: &str = "
    ldxb r2, [r1+12]
    ldxb r3, [r1+13]
    lsh r3, 0x8
    or r3, r2
    mov r0, 0x0
    jne r3, 0x8, +37
    ldxb r2, [r1+23]
    jne r2, 0x6, +35
    ldxb r2, [r1+14]
    add r1, 0xe
    and r2, 0xf
    lsh r2, 0x2
    add r1, r2
    mov r0, 0x0
    ldxh r4, [r1+12]
    add r1, 0x14
    rsh r4, 0x2
    and r4, 0x3c
    mov r2, r4
    add r2, -20
    mov r5, 0x15
    mov r3, 0x0
    jgt r5, r4, +20
    mov r5, r3
    lsh r5, 0x20
    arsh r5, 0x20
    mov r4, r1
    add r4, r5
    ldxb r5, [r4]
    jeq r5, 0x1, +4
    jeq r5, 0x0, +12
    mov r6, r3
    jeq r5, 0x5, +9
    ja +2
    add r3, 0x1
    mov r6, r3
    ldxb r3, [r4+1]
    add r3, r6
    lsh r3, 0x20
    arsh r3, 0x20
    jsgt r2, r3, -18
    ja +1
    mov r0, 0x1
    exit";

pub const TCP_SACK_BIN: [u8; 352] = [
    0x2c, 0x12, 0x0c, 0x00, 0x00, 0x00, 0x00, 0x00, //
    0x2c, 0x13, 0x0d, 0x00, 0x00, 0x00, 0x00, 0x00, //
    0x67, 0x03, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, //
    0x4f, 0x23, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, //
    0xb7, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, //
    0x55, 0x03, 0x25, 0x00, 0x08, 0x00, 0x00, 0x00, //
    0x2c, 0x12, 0x17, 0x00, 0x00, 0x00, 0x00, 0x00, //
    0x55, 0x02, 0x23, 0x00, 0x06, 0x00, 0x00, 0x00, //
    0x2c, 0x12, 0x0e, 0x00, 0x00, 0x00, 0x00, 0x00, //
    0x07, 0x01, 0x00, 0x00, 0x0e, 0x00, 0x00, 0x00, //
    0x57, 0x02, 0x00, 0x00, 0x0f, 0x00, 0x00, 0x00, //
    0x67, 0x02, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, //
    0x0f, 0x21, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, //
    0xb7, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, //
    0x3c, 0x14, 0x0c, 0x00, 0x00, 0x00, 0x00, 0x00, //
    0x07, 0x01, 0x00, 0x00, 0x14, 0x00, 0x00, 0x00, //
    0x77, 0x04, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, //
    0x57, 0x04, 0x00, 0x00, 0x3c, 0x00, 0x00, 0x00, //
    0xbf, 0x42, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, //
    0x07, 0x02, 0x00, 0x00, 0xec, 0xff, 0xff, 0xff, //
    0xb7, 0x05, 0x00, 0x00, 0x15, 0x00, 0x00, 0x00, //
    0xb7, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, //
    0x2d, 0x45, 0x14, 0x00, 0x00, 0x00, 0x00, 0x00, //
    0xbf, 0x35, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, //
    0x67, 0x05, 0x00, 0x00, 0x20, 0x00, 0x00, 0x00, //
    0xc7, 0x05, 0x00, 0x00, 0x20, 0x00, 0x00, 0x00, //
    0xbf, 0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, //
    0x0f, 0x54, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, //
    0x2c, 0x45, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, //
    0x15, 0x05, 0x04, 0x00, 0x01, 0x00, 0x00, 0x00, //
    0x15, 0x05, 0x0c, 0x00, 0x00, 0x00, 0x00, 0x00, //
    0xbf, 0x36, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, //
    0x15, 0x05, 0x09, 0x00, 0x05, 0x00, 0x00, 0x00, //
    0x05, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, //
    0x07, 0x03, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, //
    0xbf, 0x36, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, //
    0x2c, 0x43, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, //
    0x0f, 0x63, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, //
    0x67, 0x03, 0x00, 0x00, 0x20, 0x00, 0x00, 0x00, //
    0xc7, 0x03, 0x00, 0x00, 0x20, 0x00, 0x00, 0x00, //
    0x6d, 0x32, 0xee, 0xff, 0x00, 0x00, 0x00, 0x00, //
    0x05, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, //
    0xb7, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, //
    0x9d, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, //
];

pub const TCP_SACK_MATCH: [u8; 78] = [
    0x00, 0x26, 0x62, 0x2f, 0x47, 0x87, 0x00, 0x1d, //
    0x60, 0xb3, 0x01, 0x84, 0x08, 0x00, 0x45, 0x00, //
    0x00, 0x40, 0xa8, 0xde, 0x40, 0x00, 0x40, 0x06, //
    0x9d, 0x58, 0xc0, 0xa8, 0x01, 0x03, 0x3f, 0x74, //
    0xf3, 0x61, 0xe5, 0xc0, 0x00, 0x50, 0xe5, 0x94, //
    0x3f, 0x77, 0xa3, 0xc4, 0xc4, 0x80, 0xb0, 0x10, //
    0x01, 0x3e, 0x34, 0xb6, 0x00, 0x00, 0x01, 0x01, //
    0x08, 0x0a, 0x00, 0x17, 0x95, 0x6f, 0x8d, 0x9d, //
    0x9e, 0x27, 0x01, 0x01, 0x05, 0x0a, 0xa3, 0xc4, //
    0xca, 0x28, 0xa3, 0xc4, 0xcf, 0xd0, //
];

pub const TCP_SACK_NOMATCH: [u8; 66] = [
    0x00, 0x26, 0x62, 0x2f, 0x47, 0x87, 0x00, 0x1d, //
    0x60, 0xb3, 0x01, 0x84, 0x08, 0x00, 0x45, 0x00, //
    0x00, 0x40, 0xa8, 0xde, 0x40, 0x00, 0x40, 0x06, //
    0x9d, 0x58, 0xc0, 0xa8, 0x01, 0x03, 0x3f, 0x74, //
    0xf3, 0x61, 0xe5, 0xc0, 0x00, 0x50, 0xe5, 0x94, //
    0x3f, 0x77, 0xa3, 0xc4, 0xc4, 0x80, 0x80, 0x10, //
    0x01, 0x3e, 0x34, 0xb6, 0x00, 0x00, 0x01, 0x01, //
    0x08, 0x0a, 0x00, 0x17, 0x95, 0x6f, 0x8d, 0x9d, //
    0x9e, 0x27, //
];

pub fn create_memory_mapping<'a, C: ContextObject>(
    executable: &'a Executable<C>,
    stack: &'a mut AlignedMemory<{ HOST_ALIGN }>,
    heap: &'a mut AlignedMemory<{ HOST_ALIGN }>,
    additional_regions: Vec<MemoryRegion>,
    cow_cb: Option<MemoryCowCallback>,
) -> Result<MemoryMapping<'a>, EbpfError> {
    let config = executable.get_config();
    let sbpf_version = executable.get_sbpf_version();
    let regions: Vec<MemoryRegion> = vec![
        executable.get_ro_region(),
        MemoryRegion::new_writable_gapped(
            stack.as_slice_mut(),
            ebpf::MM_STACK_START,
            if !sbpf_version.dynamic_stack_frames() && config.enable_stack_frame_gaps {
                config.stack_frame_size as u64
            } else {
                0
            },
        ),
        MemoryRegion::new_writable(heap.as_slice_mut(), ebpf::MM_HEAP_START),
    ]
    .into_iter()
    .chain(additional_regions.into_iter())
    .collect();

    Ok(if let Some(cow_cb) = cow_cb {
        MemoryMapping::new_with_cow(regions, config, sbpf_version, cow_cb)?
    } else {
        MemoryMapping::new(regions, config, sbpf_version)?
    })
}

#[macro_export]
macro_rules! create_vm {
    ($vm_name:ident, $verified_executable:expr, $context_object:expr, $stack:ident, $heap:ident, $additional_regions:expr, $cow_cb:expr) => {
        let mut $stack = solana_sbpf::aligned_memory::AlignedMemory::zero_filled(
            $verified_executable.get_config().stack_size(),
        );
        let mut $heap = solana_sbpf::aligned_memory::AlignedMemory::with_capacity(0);
        let stack_len = $stack.len();
        let memory_mapping = test_utils::create_memory_mapping(
            $verified_executable,
            &mut $stack,
            &mut $heap,
            $additional_regions,
            $cow_cb,
        )
        .unwrap();
        let mut $vm_name = solana_sbpf::vm::EbpfVm::new(
            $verified_executable.get_loader().clone(),
            $verified_executable.get_sbpf_version(),
            $context_object,
            memory_mapping,
            stack_len,
        );
    };
}

#[macro_export]
macro_rules! assert_error {
    ($result:expr, $($error:expr),+) => {
        assert!(format!("{:?}", $result).contains(&format!($($error),+)));
    }
}

#[macro_export]
macro_rules! test_interpreter_and_jit {
    (override_budget => $override_budget:expr, $executable:expr, $mem:tt, $context_object:expr $(,)?) => {{
        let expected_instruction_count = $context_object.get_remaining();
        #[allow(unused_mut)]
        let mut context_object = $context_object;
        if $override_budget {
            const INSTRUCTION_METER_BUDGET: u64 = 1024;
            context_object.remaining = INSTRUCTION_METER_BUDGET;
        }
        $executable.verify::<RequisiteVerifier>().unwrap();
        let (instruction_count_interpreter, result_interpreter, interpreter_final_pc, _tracer_interpreter) = {
            let mut mem = $mem;
            let mem_region = MemoryRegion::new_writable(&mut mem, ebpf::MM_INPUT_START);
            let mut context_object = context_object.clone();
            create_vm!(
                vm,
                &$executable,
                &mut context_object,
                stack,
                heap,
                vec![mem_region],
                None
            );
            let (instruction_count_interpreter, result_interpreter) = vm.execute_program(&$executable, true);
            (
                instruction_count_interpreter,
                result_interpreter,
                vm.registers[11],
                vm.context_object_pointer.clone(),
            )
        };
        #[cfg(all(feature = "jit", not(target_os = "windows"), target_arch = "x86_64"))]
        {
            #[allow(unused_mut)]
            let compilation_result = $executable.jit_compile();
            let mut mem = $mem;
            let mem_region = MemoryRegion::new_writable(&mut mem, ebpf::MM_INPUT_START);
            create_vm!(
                vm,
                &$executable,
                &mut context_object,
                stack,
                heap,
                vec![mem_region],
                None
            );
            match compilation_result {
                Err(_) => panic!("{:?}", compilation_result),
                Ok(()) => {
                    let (instruction_count_jit, result_jit) = vm.execute_program(&$executable, false);
                    let tracer_jit = &vm.context_object_pointer;
                    let mut diverged = false;
                    if format!("{:?}", result_interpreter) != format!("{:?}", result_jit) {
                        println!(
                            "Result of interpreter ({:?}) and JIT ({:?}) diverged",
                            result_interpreter, result_jit,
                        );
                        diverged = true;
                    }
                    if instruction_count_interpreter != instruction_count_jit {
                        println!(
                            "Instruction meter of interpreter ({:?}) and JIT ({:?}) diverged",
                            instruction_count_interpreter, instruction_count_jit,
                        );
                        diverged = true;
                    }
                    if interpreter_final_pc != vm.registers[11] {
                        println!(
                            "Final PC of interpreter ({:?}) and JIT ({:?}) result diverged",
                            interpreter_final_pc, vm.registers[11],
                        );
                        diverged = true;
                    }
                    if !TestContextObject::compare_trace_log(&_tracer_interpreter, tracer_jit) {
                        let analysis = Analysis::from_executable(&$executable).unwrap();
                        let stdout = std::io::stdout();
                        analysis
                            .disassemble_trace_log(
                                &mut stdout.lock(),
                                &_tracer_interpreter.trace_log,
                            )
                            .unwrap();
                        analysis
                            .disassemble_trace_log(&mut stdout.lock(), &tracer_jit.trace_log)
                            .unwrap();
                        diverged = true;
                    }
                    assert!(!diverged);
                }
            }
        }
        if $executable.get_config().enable_instruction_meter {
            assert_eq!(
                instruction_count_interpreter, expected_instruction_count,
                "Instruction meter did not consume expected amount"
            );
        }
        result_interpreter
    }};
    ($executable:expr, $mem:tt, $context_object:expr, $expected_result:expr $(,)?) => {
        let expected_result = $expected_result;
        let result = test_interpreter_and_jit!(
            override_budget => false,
            $executable,
            $mem,
            $context_object,
        );
        assert_eq!(
            format!("{:?}", result), format!("{:?}", expected_result),
            "Unexpected result",
        );
        if !matches!(expected_result, ProgramResult::Err(solana_sbpf::error::EbpfError::ExceededMaxInstructions)) {
            test_interpreter_and_jit!(
                override_budget => true,
                $executable,
                $mem,
                $context_object,
            );
        }
    };
}

#[macro_export]
macro_rules! test_interpreter_and_jit_asm {
    ($source:expr, $config:expr, $mem:expr, $context_object:expr, $expected_result:expr $(,)?) => {
        #[allow(unused_mut)]
        {
            let mut config = $config;
            config.enable_instruction_tracing = true;
            let loader = Arc::new(BuiltinProgram::new_loader(config));
            let mut executable = assemble($source, loader).unwrap();
            test_interpreter_and_jit!(executable, $mem, $context_object, $expected_result);
        }
    };
    ($source:expr, $mem:expr, $context_object:expr, $expected_result:expr $(,)?) => {
        #[allow(unused_mut)]
        {
            test_interpreter_and_jit_asm!(
                $source,
                Config::default(),
                $mem,
                $context_object,
                $expected_result
            );
        }
    };
}

#[macro_export]
macro_rules! test_syscall_asm {
    (register, $loader:expr, $syscall_name:expr => $syscall_function:expr) => {
        let _ = $loader.register_function($syscall_name, $syscall_function).unwrap();
    };
    ($source:expr, $mem:expr, ($($syscall_name:expr => $syscall_function:expr),*$(,)?), $context_object:expr, $expected_result:expr $(,)?) => {
        let mut config = Config {
            enable_instruction_tracing: true,
            ..Config::default()
        };
        for sbpf_version in [SBPFVersion::V0, SBPFVersion::V3] {
            config.enabled_sbpf_versions = sbpf_version..=sbpf_version;
            let mut loader = BuiltinProgram::new_loader(config.clone());
            $(test_syscall_asm!(register, loader, $syscall_name => $syscall_function);)*
            let mut executable = assemble($source, Arc::new(loader)).unwrap();
            test_interpreter_and_jit!(executable, $mem, $context_object, $expected_result);
        }
    };
}

#[macro_export]
macro_rules! test_interpreter_and_jit_elf {
    (register, $loader:expr, $syscall_name:expr => $syscall_function:expr) => {
        $loader.register_function($syscall_name, $syscall_function).unwrap();
    };
    ($source:expr, $config:expr, $mem:expr, ($($syscall_name:expr => $syscall_function:expr),* $(,)?), $context_object:expr, $expected_result:expr $(,)?) => {
        let mut file = File::open($source).unwrap();
        let mut elf = Vec::new();
        file.read_to_end(&mut elf).unwrap();
        #[allow(unused_mut)]
        {
            let mut loader = BuiltinProgram::new_loader($config);
            $(test_interpreter_and_jit_elf!(register, loader, $syscall_name => $syscall_function);)*
            let mut executable = Executable::<TestContextObject>::from_elf(&elf, Arc::new(loader)).unwrap();
            test_interpreter_and_jit!(executable, $mem, $context_object, $expected_result);
        }
    };
    ($source:expr, $mem:expr, ($($syscall_name:expr => $syscall_function:expr),* $(,)?), $context_object:expr, $expected_result:expr $(,)?) => {
        let config = Config {
            enable_instruction_tracing: true,
            ..Config::default()
        };
        test_interpreter_and_jit_elf!($source, config, $mem, ($($syscall_name => $syscall_function),*), $context_object, $expected_result);
    };
}

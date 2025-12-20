#![allow(clippy::literal_string_with_formatting_args)]

use solana_sbpf::{
    elf::Executable,
    program::BuiltinProgram,
    vm::{Config, RuntimeEnvironmentSlot},
};
use std::{fs::File, io::Read, sync::Arc};
use test_utils::{create_vm, syscalls, TestContextObject};

#[test]
fn test_runtime_environment_slots() {
    let mut file = File::open("tests/elfs/relative_call_sbpfv0.so").unwrap();
    let mut elf = Vec::new();
    file.read_to_end(&mut elf).unwrap();
    let executable =
        Executable::<TestContextObject>::from_elf(&elf, Arc::new(BuiltinProgram::new_mock()))
            .unwrap();
    let mut context_object = TestContextObject::default();
    create_vm!(
        env,
        &executable,
        &mut context_object,
        stack,
        heap,
        Vec::new(),
        None
    );

    macro_rules! check_slot {
        ($env:expr, $entry:ident, $slot:ident) => {
            assert_eq!(
                unsafe {
                    std::ptr::addr_of!($env.$entry)
                        .cast::<u64>()
                        .offset_from(std::ptr::addr_of!($env).cast::<u64>()) as usize
                },
                RuntimeEnvironmentSlot::$slot as usize,
            );
        };
    }

    check_slot!(env, host_stack_pointer, HostStackPointer);
    check_slot!(env, call_depth, CallDepth);
    check_slot!(env, context_object_pointer, ContextObjectPointer);
    check_slot!(env, previous_instruction_meter, PreviousInstructionMeter);
    check_slot!(env, due_insn_count, DueInsnCount);
    check_slot!(env, stopwatch_numerator, StopwatchNumerator);
    check_slot!(env, stopwatch_denominator, StopwatchDenominator);
    check_slot!(env, registers, Registers);
    check_slot!(env, program_result, ProgramResult);
    check_slot!(env, memory_mapping, MemoryMapping);
    check_slot!(env, register_trace, RegisterTrace);
}

#[test]
fn test_builtin_program_eq() {
    let mut builtin_program_a = BuiltinProgram::new_loader(Config::default());
    let mut builtin_program_b = BuiltinProgram::new_loader(Config::default());
    let mut builtin_program_c = BuiltinProgram::new_loader(Config::default());
    builtin_program_a
        .register_function("log", syscalls::SyscallString::vm)
        .unwrap();
    builtin_program_a
        .register_function("log_64", syscalls::SyscallU64::vm)
        .unwrap();
    builtin_program_b
        .register_function("log_64", syscalls::SyscallU64::vm)
        .unwrap();
    builtin_program_b
        .register_function("log", syscalls::SyscallString::vm)
        .unwrap();
    builtin_program_c
        .register_function("log_64", syscalls::SyscallU64::vm)
        .unwrap();
    assert_eq!(builtin_program_a, builtin_program_b);
    assert_ne!(builtin_program_a, builtin_program_c);
}

#[cfg(feature = "debugger")]
#[test]
fn test_gdbstub_architecture() {
    use byteorder::{ReadBytesExt, WriteBytesExt};
    use std::io::{BufRead, BufReader, Write};
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use std::time::Duration;

    const GDBSTUB_TEST_DEBUG_PORT: &'static str = "11212";

    fn read_reply<R: BufRead>(reader: &mut R, buf: &mut Vec<u8>) -> std::io::Result<String> {
        // Clear the destination buffer first.
        buf.clear();
        // Read till the # character.
        reader.read_until(b'#', buf)?;
        // Then read exactly 2 bytes representing the checksum.
        let c = reader.read_u8()?;
        buf.write_u8(c)?;
        let c = reader.read_u8()?;
        buf.write_u8(c)?;
        let reply = String::from_utf8_lossy(buf).to_string();
        // eprintln!("gdbstub reply: {}", reply);
        Ok(reply)
    }

    // Should there are conflicts with the default debug port for this test
    // provide an option to the user to actually alter it.
    let debug_port = std::env::var("GDBSTUB_TEST_DEBUG_PORT")
        .unwrap_or(GDBSTUB_TEST_DEBUG_PORT.into())
        .parse::<u16>()
        .unwrap();

    std::thread::scope(|s| {
        s.spawn(|| {
            let mut file = File::open("./tests/elfs/relative_call_sbpfv0.so").unwrap();
            let mut elf = Vec::new();
            file.read_to_end(&mut elf).unwrap();
            let executable = Executable::<TestContextObject>::from_elf(
                &elf,
                Arc::new(BuiltinProgram::new_mock()),
            )
            .unwrap();
            let mut context_object = TestContextObject::default();
            create_vm!(
                vm,
                &executable,
                &mut context_object,
                stack,
                heap,
                Vec::new(),
                None
            );
            vm.context_object_pointer.remaining = 10_000_000_000;
            vm.debug_port = Some(debug_port);
            vm.execute_program(&executable, true).1.unwrap();
        });
        // If this is set leave the stub port listening hence
        // providing a simple test environment for playing with,
        // for instance, `solana-lldb` as a client.
        if std::env::var("DEBUG_GDBSTUB_ARCH").is_err() {
            s.spawn(|| -> std::io::Result<()> {
                let mut buf = Vec::new();
                let stub_addr =
                    SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), debug_port);
                let mut retries = 20;
                let (mut reader, mut writer) = loop {
                    retries -= 1;
                    match std::net::TcpStream::connect(&stub_addr) {
                        Err(e) => {
                            if retries == 0 {
                                return Err(e);
                            }
                            std::thread::sleep(Duration::from_millis(100));
                            continue;
                        }
                        Ok(stream) => break (BufReader::new(stream.try_clone()?), stream),
                    }
                };

                // Check the remote gdbstub's architecture is indeed `sbfv0` i.e `sbf`.
                // https://github.com/anza-xyz/llvm-project/blob/e9617fb71b9ae6c2eaab4e5bd627202fbdbf341b/lldb/source/Utility/ArchSpec.cpp#L252
                writer.write_all(b"$qXfer:features:read:target.xml:0,fff#7d")?;
                let reply = read_reply(&mut reader, &mut buf)?;
                assert!(reply.contains("<architecture>sbf</architecture>"));

                // Check the icount_remain pseudo register is 10_000_000_000 (0x2540BE400).
                writer.write_all(b"$pc#d3")?;
                let reply = read_reply(&mut reader, &mut buf)?;
                assert_eq!("+$00e40b540200*!#01", reply);

                // Gracefully shutdown the remote gdbstub.
                writer.write_all(b"$D#44")?;
                let reply = read_reply(&mut reader, &mut buf)?;
                assert_eq!("+$OK#9a", reply);
                Ok(())
            });
        }
    });
}

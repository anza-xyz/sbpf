#![allow(clippy::literal_string_with_formatting_args)]

use solana_sbpf::{
    program::{BuiltinFunctionDefinition, BuiltinProgram},
    vm::Config,
};
use test_utils::syscalls;

#[test]
fn test_builtin_program_eq() {
    let mut builtin_program_a = BuiltinProgram::new_loader(Config::default());
    let mut builtin_program_b = BuiltinProgram::new_loader(Config::default());
    let mut builtin_program_c = BuiltinProgram::new_loader(Config::default());
    syscalls::SyscallString::register(&mut builtin_program_a, "log").unwrap();
    syscalls::SyscallU64::register(&mut builtin_program_a, "log_64").unwrap();
    syscalls::SyscallU64::register(&mut builtin_program_b, "log_64").unwrap();
    syscalls::SyscallString::register(&mut builtin_program_b, "log").unwrap();
    syscalls::SyscallU64::register(&mut builtin_program_c, "log_64").unwrap();
    assert_eq!(builtin_program_a, builtin_program_b);
    assert_ne!(builtin_program_a, builtin_program_c);
}

#[cfg(feature = "debugger")]
#[test]
fn test_gdbstub_architecture() {
    use byteorder::{ReadBytesExt, WriteBytesExt};
    use solana_sbpf::elf::Executable;
    use solana_sbpf::vm::{CallFrame, ExecutionMode};
    use std::fs::File;
    use std::io::{BufRead, BufReader, Read, Write};
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use std::sync::Arc;
    use std::time::Duration;
    use test_utils::{create_vm, TestContextObject};

    const GDBSTUB_TEST_DEBUG_PORT: &str = "11212";
    const METADATA: &str = "6CSmiViMaAguKgxNVwU8TWMPViQbtL5KKoFrDwWwtYNR";

    fn read_reply<R: BufRead>(reader: &mut R) -> std::io::Result<String> {
        let mut buf = Vec::new();

        // Read till the # character.
        reader.read_until(b'#', &mut buf)?;
        // Then read exactly 2 bytes representing the checksum.
        let c = reader.read_u8()?;
        buf.write_u8(c)?;
        let c = reader.read_u8()?;
        buf.write_u8(c)?;
        let reply = String::from_utf8_lossy(&buf).to_string();
        // eprintln!("gdbstub reply: {}", reply);
        Ok(reply)
    }

    fn send_packet(writer: &mut impl Write, payload: &str) -> std::io::Result<()> {
        let checksum = payload
            .bytes()
            .fold(0u8, |checksum, byte| checksum.wrapping_add(byte));
        write!(writer, "${payload}#{checksum:02x}")
    }

    fn decode_hex_packet(reply: &str) -> Vec<u8> {
        let packet = reply.strip_prefix('+').unwrap_or(reply);
        let encoded = packet
            .strip_prefix('$')
            .and_then(|packet| packet.split_once('#'))
            .map(|(payload, _)| payload)
            .expect("GDB response packet");
        let encoded = encoded.strip_prefix('O').unwrap_or(encoded);

        let mut expanded = Vec::new();
        let mut bytes = encoded.bytes();
        while let Some(byte) = bytes.next() {
            if byte == b'*' {
                let repeat = bytes.next().expect("RLE repeat count");
                let previous = *expanded.last().expect("RLE previous byte");
                expanded.extend(std::iter::repeat_n(previous, (repeat - 29) as usize));
            } else {
                expanded.push(byte);
            }
        }

        expanded
            .as_chunks::<2>()
            .0
            .iter()
            .map(|digits| u8::from_str_radix(std::str::from_utf8(digits).unwrap(), 16).unwrap())
            .collect()
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
            let mut call_frames = vec![CallFrame::default(); Config::default().max_call_depth];
            create_vm!(
                vm,
                &executable,
                &mut context_object,
                stack,
                heap,
                Vec::new(),
                None
            );
            vm.context().remaining = 10_000_000_000;
            vm.debug_port = Some(debug_port);
            vm.debug_metadata = Some(METADATA.into());
            vm.execute_program(
                &executable,
                &mut ExecutionMode::Interpreted,
                &mut call_frames,
            )
            .1
            .unwrap();
        });
        // If this is set leave the stub port listening hence
        // providing a simple test environment for playing with,
        // for instance, `solana-lldb` as a client.
        if std::env::var("DEBUG_GDBSTUB_ARCH").is_err() {
            let client_jh = s.spawn(|| -> std::io::Result<()> {
                let stub_addr =
                    SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), debug_port);
                let mut retries = 20;
                let (mut reader, mut writer) = loop {
                    retries -= 1;
                    match std::net::TcpStream::connect(stub_addr) {
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

                // Check the remote gdbstub's architecture is indeed `sbpfv0` i.e `sbpf`.
                // https://github.com/anza-xyz/llvm-project/blob/cefd64747bb027d9755efa4d674ee4cf5772e7c2/lldb/source/Utility/ArchSpec.cpp#L252
                writer.write_all(b"$qXfer:features:read:target.xml:0,fff#7d")?;
                let reply = read_reply(&mut reader)?;
                assert!(reply.contains("<architecture>sbpf</architecture>"));

                // Check the icount_remain pseudo register is 10_000_000_000 (0x2540BE400).
                writer.write_all(b"$pc#d3")?;
                let reply = read_reply(&mut reader)?;
                assert_eq!(decode_hex_packet(&reply), 10_000_000_000u64.to_le_bytes());

                // Check the monitor command returns the expected metadata.
                writer.write_all(b"$qRcmd,6d65746164617461#9d")?;
                let reply = read_reply(&mut reader)?;
                assert_eq!(
                    decode_hex_packet(&reply),
                    format!("{METADATA}\n").as_bytes()
                );
                let reply = read_reply(&mut reader)?;
                assert_eq!("$OK#9a", reply);

                // Stop in the function called by entrypoint so the runtime
                // contains an actual saved caller frame.
                send_packet(&mut writer, "P1=0000000002000000")?;
                let reply = read_reply(&mut reader)?;
                assert!(reply.contains("$OK#"));
                send_packet(&mut writer, "Z0,120,0")?;
                let reply = read_reply(&mut reader)?;
                assert!(reply.contains("$OK#"));
                send_packet(&mut writer, "c")?;
                let reply = read_reply(&mut reader)?;
                assert!(reply.contains("$T05"));

                send_packet(&mut writer, "qSBPFCallStack:1")?;
                let reply = read_reply(&mut reader)?;
                let response = decode_hex_packet(&reply);
                assert_eq!(response.len(), 2 * 2 * std::mem::size_of::<u64>());
                let values: Vec<_> = response
                    .as_chunks::<{ std::mem::size_of::<u64>() }>()
                    .0
                    .iter()
                    .map(|value| u64::from_le_bytes(*value))
                    .collect();
                assert_eq!(values[0], 0x120);
                assert_eq!(values[2], 0x168);
                assert!(values[1] > values[3]);

                // Gracefully shutdown the remote gdbstub.
                writer.write_all(b"$D#44")?;
                let reply = read_reply(&mut reader)?;
                assert_eq!("+$OK#9a", reply);
                Ok(())
            });

            client_jh.join().unwrap().expect("client error");
        }
    });
}

#[cfg(feature = "debugger")]
#[test]
fn test_gdbstub_sbpfv3_pc_and_text() {
    use gdbstub::{
        conn::Connection,
        stub::{state_machine::GdbStubStateMachine, GdbStub},
    };
    use solana_sbpf::{elf::Executable, interpreter::Interpreter, vm::CallFrame};
    use std::convert::{Infallible, TryInto};
    use std::sync::Arc;
    use test_utils::{create_vm, TestContextObject};

    struct TestConnection(Vec<u8>);

    impl Connection for TestConnection {
        type Error = Infallible;

        fn write(&mut self, byte: u8) -> Result<(), Self::Error> {
            self.0.push(byte);
            Ok(())
        }

        fn flush(&mut self) -> Result<(), Self::Error> {
            Ok(())
        }
    }

    let elf = std::fs::read("tests/elfs/relative_call.so").unwrap();
    let executable =
        Executable::<TestContextObject>::from_elf(&elf, Arc::new(BuiltinProgram::new_mock()))
            .unwrap();
    let (text_vaddr, text) = executable.get_text_bytes();
    let entry_offset = executable.get_entrypoint_instruction_offset() * 8;
    let expected_pc = text_vaddr + entry_offset as u64;
    let expected_instruction = &text[entry_offset..entry_offset + 8];

    let mut context_object = TestContextObject::default();
    let mut call_frames = vec![CallFrame::default(); Config::default().max_call_depth];
    // Seed a caller to verify that the packet uses virtual addresses for both
    // current and historical PCs, not the legacy ELF file-offset convention.
    call_frames[0].target_pc = executable.get_entrypoint_instruction_offset() as u64 + 1;
    create_vm!(
        vm,
        &executable,
        &mut context_object,
        stack,
        heap,
        Vec::new(),
        None
    );
    let mut registers = vm.registers;
    vm.call_depth = 1;
    registers[11] = executable.get_entrypoint_instruction_offset() as u64;
    let expected_fp = registers[10];
    let mut interpreter = Interpreter::new(&mut vm, &executable, registers, &mut call_frames);

    // Drive the real protocol parser and target handlers synchronously. Each
    // complete request produces its reply without sockets or worker threads.
    let mut state = Some(
        GdbStub::new(TestConnection(Vec::new()))
            .run_state_machine(&mut interpreter)
            .unwrap(),
    );
    let mut request = |packet: &str| {
        let checksum = packet.bytes().fold(0u8, u8::wrapping_add);
        for byte in format!("${packet}#{checksum:02x}").bytes() {
            let GdbStubStateMachine::Idle(stub) = state.take().unwrap() else {
                panic!("expected an idle debugger before receiving a request");
            };
            state = Some(stub.incoming_data(&mut interpreter, byte).unwrap());
        }
        let connection = match state.as_mut().unwrap() {
            GdbStubStateMachine::Idle(stub) => stub.borrow_conn(),
            GdbStubStateMachine::Disconnected(stub) => stub.borrow_conn(),
            _ => panic!("unexpected debugger state after request"),
        };
        let reply = String::from_utf8(std::mem::take(&mut connection.0)).unwrap();
        let payload = reply.trim_start_matches('+').strip_prefix('$').unwrap();
        let (payload, checksum) = payload.rsplit_once('#').unwrap();
        assert_eq!(
            payload.bytes().fold(0u8, u8::wrapping_add),
            u8::from_str_radix(checksum, 16).unwrap()
        );
        let mut expanded = Vec::new();
        let mut bytes = payload.bytes();
        while let Some(byte) = bytes.next() {
            if byte == b'*' {
                let count = bytes.next().unwrap() - 29;
                expanded.extend(std::iter::repeat_n(
                    *expanded.last().unwrap(),
                    count as usize,
                ));
            } else {
                expanded.push(byte);
            }
        }
        String::from_utf8(expanded).unwrap()
    };

    let architecture = request("qXfer:features:read:target.xml:0,fff");
    assert!(architecture.contains("<architecture>sbpfv3</architecture>"));

    let pc = request("pb");
    let pc_bytes: Vec<_> = pc
        .as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect();
    assert_eq!(
        u64::from_le_bytes(pc_bytes.try_into().unwrap()),
        expected_pc
    );

    let frames = request("qSBPFCallStack:1");
    let expected_frames: String = [expected_pc, expected_fp, expected_pc + 8, 0]
        .iter()
        .copied()
        .flat_map(u64::to_le_bytes)
        .map(|byte| format!("{byte:02x}"))
        .collect();
    assert_eq!(frames, expected_frames);

    let instruction = request(&format!("m{expected_pc:x},8"));
    let expected_hex: String = expected_instruction
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    assert_eq!(instruction, expected_hex);

    // Debugger reads are byte-granular, including at the ends of .text.
    for offset in [0, text.len() - 1] {
        let address = text_vaddr + offset as u64;
        assert_eq!(
            request(&format!("m{address:x},1")),
            format!("{:02x}", text[offset])
        );
    }

    assert_eq!(request("D"), "OK");
    assert!(matches!(state, Some(GdbStubStateMachine::Disconnected(_))));
}

#[cfg(feature = "debugger")]
#[test]
fn test_debugger_dynamic_recursive_frames() {
    use gdbstub::{common::Tid, target::ext::sbpf::Sbpf};
    use solana_sbpf::{
        assembler::assemble, ebpf, interpreter::Interpreter, program::SBPFVersion, vm::CallFrame,
    };
    use std::sync::Arc;
    use test_utils::{create_vm, TestContextObject};

    for version in [SBPFVersion::V1, SBPFVersion::V2] {
        let config = Config {
            enabled_sbpf_versions: version..=version,
            enable_instruction_meter: false,
            ..Config::default()
        };
        let initial_fp = ebpf::MM_STACK_START + config.stack_size() as u64;
        let executable = assemble::<TestContextObject>(
            "mov64 r0, 2
             call function_recurse
             exit
             function_recurse:
             jeq r0, 0, done
             add64 r0, -1
             call function_recurse
             exit
             done:
             add64 r10, -64
             exit",
            Arc::new(BuiltinProgram::new_loader(config)),
        )
        .unwrap();
        let mut context = TestContextObject::default();
        create_vm!(vm, &executable, &mut context, stack, heap, Vec::new(), None);
        let mut registers = [0; 12];
        registers[10] = initial_fp;
        registers[11] = executable.get_entrypoint_instruction_offset() as u64;
        let mut frames = vec![CallFrame::default(); executable.get_config().max_call_depth];
        let mut interpreter = Interpreter::new(&mut vm, &executable, registers, &mut frames);
        let snapshot = |interpreter: &Interpreter<TestContextObject>| {
            let mut result = Vec::new();
            interpreter
                .sbpf_call_stack(Tid::new(1).unwrap(), &mut |pc, fp| result.push((pc, fp)))
                .unwrap();
            result
        };
        // Reach the deepest recursive invocation, before it adjusts r10.
        for _ in 0..20 {
            if interpreter.reg[11] == 7 {
                break;
            }
            assert!(interpreter.step());
        }
        assert_eq!(interpreter.reg[11], 7);
        let before = snapshot(&interpreter);
        assert_eq!(before.len(), 4);
        assert!(before.iter().all(|(_, fp)| *fp == initial_fp));
        // Recursive callers can share both their return PC and r10.
        assert_eq!(before[1], before[2]);
        assert!(interpreter.step());
        let adjusted = snapshot(&interpreter);
        assert_eq!(adjusted[0].1, initial_fp - 64);
        assert_eq!(&adjusted[1..], &before[1..]);
        // Returning restores the caller's register state and removes one frame.
        assert!(interpreter.step());
        assert_eq!(snapshot(&interpreter), adjusted[1..]);
    }
}

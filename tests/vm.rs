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

    const GDBSTUB_TEST_DEBUG_PORT: &'static str = "11212";
    const METADATA: &'static str = "6CSmiViMaAguKgxNVwU8TWMPViQbtL5KKoFrDwWwtYNR";

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

                // Check the remote gdbstub's architecture is indeed `sbpfv0` i.e `sbpf`.
                // https://github.com/anza-xyz/llvm-project/blob/cefd64747bb027d9755efa4d674ee4cf5772e7c2/lldb/source/Utility/ArchSpec.cpp#L252
                writer.write_all(b"$qXfer:features:read:target.xml:0,fff#7d")?;
                let reply = read_reply(&mut reader)?;
                assert!(reply.contains("<architecture>sbpf</architecture>"));

                // Check the icount_remain pseudo register is 10_000_000_000 (0x2540BE400).
                writer.write_all(b"$pc#d3")?;
                let reply = read_reply(&mut reader)?;
                assert_eq!("+$00e40b540200*!#01", reply);

                // Check the monitor command returns the expected metadata.
                writer.write_all(b"$qRcmd,6d65746164617461#9d")?;
                let reply = read_reply(&mut reader)?;
                assert_eq!(
                    "+$O3643536d6956694d614167754b67784e5677553854574d5056695162744c3\
54b4b6f4672447757* 4594e520a#9e",
                    reply
                );
                let reply = read_reply(&mut reader)?;
                assert_eq!("$OK#9a", reply);

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
    use solana_sbpf::elf::Executable;
    use solana_sbpf::vm::{CallFrame, ExecutionMode};
    use std::convert::TryInto;
    use std::io::{BufRead, BufReader, Read, Write};
    use std::net::{TcpListener, TcpStream};
    use std::sync::Arc;
    use std::time::Duration;
    use test_utils::{create_vm, TestContextObject};

    fn request(reader: &mut BufReader<TcpStream>, writer: &mut TcpStream, packet: &str) -> String {
        let checksum = packet.bytes().fold(0u8, u8::wrapping_add);
        write!(writer, "${packet}#{checksum:02x}").unwrap();
        let mut reply = Vec::new();
        reader.read_until(b'#', &mut reply).unwrap();
        let mut checksum = [0; 2];
        reader.read_exact(&mut checksum).unwrap();
        let reply = String::from_utf8(reply).unwrap();
        let payload = reply
            .trim_start_matches('+')
            .trim_start_matches('$')
            .trim_end_matches('#');
        let mut expanded = Vec::new();
        let mut bytes = payload.bytes();
        while let Some(byte) = bytes.next() {
            if byte == b'*' {
                let count = bytes.next().unwrap() - 29;
                expanded.extend(std::iter::repeat(*expanded.last().unwrap()).take(count as usize));
            } else {
                expanded.push(byte);
            }
        }
        String::from_utf8(expanded).unwrap()
    }

    let elf = std::fs::read("tests/elfs/relative_call.so").unwrap();
    let executable =
        Executable::<TestContextObject>::from_elf(&elf, Arc::new(BuiltinProgram::new_mock()))
            .unwrap();
    let (text_vaddr, text) = executable.get_text_bytes();
    let entry_offset = executable.get_entrypoint_instruction_offset() * 8;
    let expected_pc = text_vaddr + entry_offset as u64;
    let expected_instruction = &text[entry_offset..entry_offset + 8];

    let port = TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    std::thread::scope(|scope| {
        scope.spawn(|| {
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
            vm.context().remaining = 10_000_000;
            vm.debug_port = Some(port);
            vm.execute_program(
                &executable,
                &mut ExecutionMode::Interpreted,
                &mut call_frames,
            );
        });

        let address = format!("127.0.0.1:{port}");
        let mut writer = (0..20)
            .find_map(|_| match TcpStream::connect(&address) {
                Ok(stream) => Some(stream),
                Err(_) => {
                    std::thread::sleep(Duration::from_millis(100));
                    None
                }
            })
            .expect("debugger did not start");
        writer
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let mut reader = BufReader::new(writer.try_clone().unwrap());

        let architecture = request(
            &mut reader,
            &mut writer,
            "qXfer:features:read:target.xml:0,fff",
        );
        assert!(architecture.contains("<architecture>sbpfv3</architecture>"));

        let pc = request(&mut reader, &mut writer, "pb");
        let pc_bytes: Vec<_> = pc
            .as_bytes()
            .chunks_exact(2)
            .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
            .collect();
        assert_eq!(
            u64::from_le_bytes(pc_bytes.try_into().unwrap()),
            expected_pc
        );

        let instruction = request(&mut reader, &mut writer, &format!("m{expected_pc:x},8"));
        let expected_hex: String = expected_instruction
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();
        assert_eq!(instruction, expected_hex);

        assert_eq!(request(&mut reader, &mut writer, "D"), "OK");
    });
}

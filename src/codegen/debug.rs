//! Looking at the machine code that `codegen` generates, in debuggers, profilers and disassemblers.
//!
//! The generated code lives in a handful of regions (see [`Region`]), which this module describes
//! and can write out as ELF files, for `objdump -d` and `nm`, see [`write_elf`].
//!
//! The `codegen-debug` feature compiles in the debugging aids below, which environment variables
//! control at runtime, see [`Options`]:
//!
//! - `SBPF_DEBUG_STACK_CHECKS` (on unless `0`, `false`, `off` or `no`): traps in the generated
//!   code if the stack is misaligned for a call.
//! - `SBPF_DEBUG_CODE_DIR` (Linux, off unless set): the running code itself is generated into ELF files
//!   in that directory, so that the tools know its symbols in the running process: the supporting
//!   code, each interpreter and each JIT program are written through a shared mapping of
//!   `sbpf-<pid>-<label>.elf`, with `<label>` being `supports`, `interpreter-<version>` or
//!   `jit-<n>`. The directory must allow executable mappings (not `noexec`). `/proc/<pid>/maps`
//!   names the files. Those of the JIT programs stay on disk after the programs are dropped, as the
//!   record of them.
//! - `SBPF_DEBUG_GDB_INTEGRATION` (Linux, on unless `0`, `false`, `off` or `no`): once the code is final, it
//!   is registered with the GDB JIT interface, so that `gdb` resolves the symbols without being
//!   told about any files.

use super::x64::{self, supporting_code::SupportingCode, InterpreterGenerator};
use super::{AuxTemplate, JitTemplates, TemplateOpcode};
use crate::disassembler::disassemble_instruction;
use crate::ebpf;
use crate::elf::Executable;
use crate::program::{BuiltinProgram, FunctionRegistry, JitProgram, SBPFVersion};
use crate::static_analysis::DummyContextObject;
use crate::vm::ContextObject;
use std::collections::BTreeMap;
use std::convert::TryFrom;
use std::fmt;
use std::io;
use std::path::Path;

/// Which of the debugging aids are on, see the module documentation.
#[derive(Clone, Debug)]
pub struct Options {
    /// `SBPF_DEBUG_STACK_CHECKS`.
    pub stack_checks: bool,
    /// `SBPF_DEBUG_CODE_DIR`, the directory to generate the code into files in.
    pub code_dir: Option<std::path::PathBuf>,
    /// `SBPF_DEBUG_GDB_INTEGRATION`.
    pub gdb_jit: bool,
}

/// The `Options` of the process, read from the environment once, before anything is generated.
pub fn options() -> &'static Options {
    static OPTIONS: std::sync::LazyLock<Options> = std::sync::LazyLock::new(|| Options {
        stack_checks: env_flag("SBPF_DEBUG_STACK_CHECKS"),
        code_dir: std::env::var_os("SBPF_DEBUG_CODE_DIR").map(std::path::PathBuf::from),
        gdb_jit: env_flag("SBPF_DEBUG_GDB_INTEGRATION"),
    });
    &OPTIONS
}

/// Whether the environment variable `name` leaves its debugging aid on, which it is by default.
///
/// # Panics
///
/// If the value is not one of the recognized ones, rather than guessing what was meant.
fn env_flag(name: &str) -> bool {
    let Some(value) = std::env::var_os(name) else {
        return true;
    };
    match value.to_str().map(str::to_ascii_lowercase).as_deref() {
        Some("1" | "true" | "on" | "yes") => true,
        Some("0" | "false" | "off" | "no") => false,
        _ => panic!(
            "{} must be 0/1, false/true, off/on or no/yes, not {:?}",
            name, value
        ),
    }
}

/// A function in generated code.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Symbol {
    /// Name in the symbol table.
    pub name: String,
    /// Where the function starts.
    pub address: usize,
    /// In bytes.
    pub size: usize,
}

/// A contiguous piece of generated code.
#[derive(Clone, Debug)]
pub struct Region {
    /// Name of the ELF section, e.g. `.text.jit`.
    pub name: String,
    /// The address `bytes` are at.
    pub start: usize,
    /// The code, as it is in memory.
    pub bytes: Vec<u8>,
    /// Sorted by address.
    pub symbols: Vec<Symbol>,
}

/// A relocation of a JIT template, which is resolved when the template is instantiated for a BPF
/// instruction.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RelocationInfo {
    /// What the field is set to, by the name of the internal relocation kind.
    pub kind: String,
    /// Offset of the 32-bit field in the template.
    pub field_offset: usize,
    /// What the field holds in the template, to which the target of the relocation is added.
    pub addend: i32,
}

impl fmt::Display for RelocationInfo {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "{} at +{:#x}, addend {}",
            self.kind, self.field_offset, self.addend
        )
    }
}

/// The JIT template of a BPF instruction.
#[derive(Clone, Debug)]
pub struct Template {
    /// The machine code, before the relocations are applied.
    pub code: Vec<u8>,
    /// In the order of the template.
    pub relocations: Vec<RelocationInfo>,
}

/// The code shared by the JIT output and the interpreters.
pub fn supporting_code() -> Region {
    supporting_code_region(SupportingCode::get())
}

/// The interpreter for `version`, with a symbol for each of its steps.
///
/// # Panics
///
/// If `codegen` does not support `version`.
pub fn interpreter(version: SBPFVersion) -> Region {
    let interpreter = x64::interpreter(version);
    let start = interpreter.buffer as usize;
    // SAFETY:
    //
    // Contract from `read_memory`: the memory must be readable, initialized and not written to.
    // Evidence: `buffer` is the interpreter's table of `STEP_TABLE_SIZE` bytes, read-execute and
    // never freed once generated, which `x64::interpreter` returned.
    let bytes = unsafe { read_memory(start, InterpreterGenerator::STEP_TABLE_SIZE) };
    Region {
        name: format!(".text.interpreter_{}", version_name(version)),
        start,
        bytes,
        symbols: interpreter_symbols(version, start, &interpreter.step_lens),
    }
}

/// The JIT output `program` of `executable`, with a symbol per BPF instruction.
///
/// # Panics
///
/// If `program` was not produced by `codegen`.
pub fn jit<C: ContextObject>(executable: &Executable<C>, program: &JitProgram) -> Region {
    assert!(program.dynasm, "not a program of codegen");
    jit_region(
        x64::jit_templates(executable.get_sbpf_version()),
        executable,
        program,
    )
}

/// The JIT template for the instructions with the `TemplateOpcode` `opcode`: the opcode of the
/// instruction in bits 0 to 7, the destination register in 8 to 11 and the source register in 12
/// to 15.
///
/// # Panics
///
/// If `codegen` does not support `version`.
pub fn template(version: SBPFVersion, opcode: u16) -> Template {
    let templates = x64::jit_templates(version);
    let index = TemplateOpcode(opcode).index();
    let layout = templates.layouts[index];
    let relocations = &templates.relocations[index][..usize::from(layout.num_relocations)];
    let code = templates.code[index][..layout.len()].to_vec();
    Template {
        relocations: relocations
            .iter()
            .map(|relocation| {
                let field = usize::from(relocation.field);
                let addend = *code[field..].first_chunk::<4>().unwrap();
                RelocationInfo {
                    kind: format!("{:?}", relocation.kind),
                    field_offset: field,
                    addend: i32::from_le_bytes(addend),
                }
            })
            .collect(),
        code,
    }
}

/// Write the `regions` into an ELF file at `path`, which can be disassembled and mapped at the
/// addresses of the regions.
pub fn write_elf(path: &Path, regions: &[Region]) -> io::Result<()> {
    std::fs::write(path, build_elf(regions).0)
}

/// Sort `named` addresses, and make each symbol extend to the next one, and the last to `end`.
fn sized_symbols(mut named: Vec<(String, usize)>, end: usize) -> Vec<Symbol> {
    named.sort_by_key(|(_, address)| *address);
    let mut symbols: Vec<Symbol> = Vec::with_capacity(named.len());
    for (name, address) in named {
        if let Some(previous) = symbols.last_mut() {
            previous.size = address.saturating_sub(previous.address);
        }
        symbols.push(Symbol {
            name,
            address,
            size: end.saturating_sub(address),
        });
    }
    symbols
}

/// Copy `len` bytes of memory at `start`.
///
/// # Safety
///
/// The memory must be readable and initialized, and not written to meanwhile.
unsafe fn read_memory(start: usize, len: usize) -> Vec<u8> {
    // SAFETY:
    //
    // Contract from `slice::from_raw_parts`: the memory must be valid for reads of the length,
    // initialized, and not mutated while borrowed.
    // Evidence: all of it is the contract of `read_memory`.
    unsafe { std::slice::from_raw_parts(start as *const u8, len) }.to_vec()
}

fn supporting_code_region(supports: &SupportingCode) -> Region {
    let (range, symbols) = supporting_code_symbols(supports);
    // SAFETY:
    //
    // Contract from `read_memory`: the memory must be readable, initialized and not written to.
    // Evidence: the range is the code that `SupportingCode` generated into its allocation, which
    // is read-execute after the generation, and is never freed.
    let bytes = unsafe { read_memory(range.start, range.len()) };
    Region {
        name: ".text.supports".to_string(),
        start: range.start,
        bytes,
        symbols,
    }
}

/// The address range of the supporting code, and its symbols.
fn supporting_code_symbols(supports: &SupportingCode) -> (std::ops::Range<usize>, Vec<Symbol>) {
    let (range, named) = supports.debug_symbols();
    let symbols = sized_symbols(named, range.end as usize);
    (range.start as usize..range.end as usize, symbols)
}

fn version_name(version: SBPFVersion) -> String {
    format!("{version:?}").to_lowercase()
}

/// The name of the BPF instruction with the given operation, for the symbols.
fn mnemonic(
    loader: &BuiltinProgram<DummyContextObject>,
    version: SBPFVersion,
    insn: &ebpf::Insn,
) -> String {
    let text = disassemble_instruction(
        insn,
        insn.ptr,
        &BTreeMap::new(),
        &FunctionRegistry::default(),
        loader,
        version,
    );
    match text.split(' ').next() {
        Some(name) if name != "unknown" => name.to_string(),
        _ => format!("op{:02x}", insn.opc),
    }
}

/// The symbols of the steps of the interpreter at `start`, one for each of the opcodes, as long as
/// the code of the step: the rest of its slot is padding. `step_lens` is indexed like the steps.
fn interpreter_symbols(version: SBPFVersion, start: usize, step_lens: &[u8]) -> Vec<Symbol> {
    let loader = BuiltinProgram::<DummyContextObject>::new_mock();
    let mut symbols = Vec::with_capacity(TemplateOpcode::COUNT);
    for opcode in 0..=u16::MAX {
        let (op, dst, src) = (opcode as u8, (opcode >> 8) & 0xf, opcode >> 12);
        let insn = ebpf::Insn {
            ptr: 0,
            opc: op,
            dst: dst as u8,
            src: src as u8,
            off: 0,
            // Valid for `be` and `le`, which the disassembler complains about otherwise.
            imm: 16,
        };
        let index = TemplateOpcode(opcode).index();
        symbols.push(Symbol {
            name: format!(
                "step_{op:02x}_{}_dst{dst}_src{src}",
                mnemonic(&loader, version, &insn)
            ),
            address: start
                .checked_add(index << InterpreterGenerator::STEP_SIZE_LOG2)
                .unwrap(),
            size: usize::from(step_lens[index]),
        });
    }
    symbols
}

fn jit_region<const SIZE: usize, C: ContextObject>(
    templates: &JitTemplates<SIZE>,
    executable: &Executable<C>,
    program: &JitProgram,
) -> Region {
    let text = program.text_section();
    Region {
        name: ".text.jit".to_string(),
        start: text.as_ptr() as usize,
        bytes: text.to_vec(),
        symbols: jit_symbols(templates, executable, program),
    }
}

/// The symbols of the sealed `program`: one per BPF instruction, and the templates around them.
fn jit_symbols<const SIZE: usize, C: ContextObject>(
    templates: &JitTemplates<SIZE>,
    executable: &Executable<C>,
    program: &JitProgram,
) -> Vec<Symbol> {
    let version = executable.get_sbpf_version();
    let text = program.text_section();
    let start = text.as_ptr() as usize;
    let bpf = executable.get_text_bytes().1;
    let loader = BuiltinProgram::<DummyContextObject>::new_mock();

    let names = [
        "invalid_call_target",
        "sig_invalid_insn",
        "sig_meter_exceeded",
    ];
    let mut named: Vec<_> = names
        .iter()
        .zip(templates.shared_offsets())
        .map(|(name, offset)| (name.to_string(), start.checked_add(offset).unwrap()))
        .collect();
    for (pc, &offset) in program.pc_section().iter().enumerate() {
        // The second halves of `lddw` have no code.
        if offset == JitTemplates::<SIZE>::INVALID_CALL_TARGET {
            continue;
        }
        let insn = ebpf::get_insn_unchecked(bpf, pc);
        named.push((
            format!("pc_{pc}_{}", mnemonic(&loader, version, &insn)),
            start.checked_add(offset as usize).unwrap(),
        ));
    }
    let overrun_len = templates.aux_layout(AuxTemplate::ExecutionOverrun).len();
    let overrun = start
        .checked_add(text.len())
        .unwrap()
        .checked_sub(overrun_len)
        .unwrap();
    named.push(("execution_overrun".to_string(), overrun));

    let mut symbols = sized_symbols(named, start.checked_add(text.len()).unwrap());
    // The padding that may follow the shared templates is not part of the last of them.
    let last = AuxTemplate::SHARED.len().checked_sub(1).unwrap();
    let last_len = templates.aux_layout(AuxTemplate::SHARED[last]).len();
    symbols[last].size = symbols[last].size.min(last_len);
    symbols
}

const PAGE_ALIGNMENT: usize = 4096;
const ELF_HEADER_SIZE: usize = 64;
const PROGRAM_HEADER_SIZE: usize = 56;
const SECTION_HEADER_SIZE: usize = 64;
const SYMBOL_SIZE: usize = 24;

fn put_u16(out: &mut Vec<u8>, value: u16) {
    out.extend_from_slice(&value.to_le_bytes());
}

fn put_u32(out: &mut Vec<u8>, value: u32) {
    out.extend_from_slice(&value.to_le_bytes());
}

fn put_u64(out: &mut Vec<u8>, value: u64) {
    out.extend_from_slice(&value.to_le_bytes());
}

/// Append `name` to the string table `strings`, and return its offset.
fn put_string(strings: &mut Vec<u8>, name: &str) -> u32 {
    let offset = u32::try_from(strings.len()).unwrap();
    strings.extend_from_slice(name.as_bytes());
    strings.push(0);
    offset
}

/// Pad `out` with zeros to `offset`.
fn pad_to(out: &mut Vec<u8>, offset: usize) {
    assert!(out.len() <= offset);
    out.resize(offset, 0);
}

#[derive(Clone, Copy)]
struct SectionHeader {
    name: u32,
    kind: u32,
    flags: u64,
    address: u64,
    offset: u64,
    size: u64,
    link: u32,
    info: u32,
    alignment: u64,
    entry_size: u64,
}

fn put_section_header(out: &mut Vec<u8>, header: &SectionHeader) {
    put_u32(out, header.name);
    put_u32(out, header.kind);
    put_u64(out, header.flags);
    put_u64(out, header.address);
    put_u64(out, header.offset);
    put_u64(out, header.size);
    put_u32(out, header.link);
    put_u32(out, header.info);
    put_u64(out, header.alignment);
    put_u64(out, header.entry_size);
}

/// An ELF file with the `regions`, and the offset in it of the bytes of each of them.
///
/// Every region is a section and a `PT_LOAD` segment at its address, with the file offset
/// congruent to the address modulo the page size so that the file can be mapped at it. The file
/// has all the symbols of the regions in `.symtab`.
fn build_elf(regions: &[Region]) -> (Vec<u8>, Vec<usize>) {
    // The segments have to be in the order of their addresses.
    let mut order: Vec<usize> = (0..regions.len()).collect();
    order.sort_by_key(|&index| regions[index].start);
    let mut offsets = vec![0; regions.len()];
    let mut segments = Vec::with_capacity(regions.len());
    let mut cursor = ELF_HEADER_SIZE
        .checked_add(regions.len().checked_mul(PROGRAM_HEADER_SIZE).unwrap())
        .unwrap();
    for &index in &order {
        let region = &regions[index];
        let in_page = region.start & (PAGE_ALIGNMENT - 1);
        let offset = cursor
            .next_multiple_of(PAGE_ALIGNMENT)
            .checked_add(in_page)
            .unwrap();
        offsets[index] = offset;
        cursor = offset.checked_add(region.bytes.len()).unwrap();
        segments.push(Segment {
            name: &region.name,
            start: region.start,
            len: region.bytes.len(),
            offset,
            symbols: &region.symbols,
        });
    }
    let (head, tail_offset, tail) = elf_parts(&segments, cursor);
    let mut out = head;
    for &index in &order {
        pad_to(&mut out, offsets[index]);
        out.extend_from_slice(&regions[index].bytes);
    }
    pad_to(&mut out, tail_offset);
    out.extend_from_slice(&tail);
    (out, offsets)
}

/// A region of code in an ELF file.
struct Segment<'a> {
    /// Name of the section.
    name: &'a str,
    /// The address the code is at when running.
    start: usize,
    /// Of the code in bytes.
    len: usize,
    /// Of the code in the file, which is congruent to `start` modulo the page size.
    offset: usize,
    symbols: &'a [Symbol],
}

/// The parts of the ELF file with the `segments` (sorted by address) that are not the code: the
/// headers, which are to be written at the start of the file, and everything that follows the
/// code, which is `end` bytes into the file, so it is written at the returned offset.
///
/// Splitting it like this lets the code be written in place by whoever owns it, and the rest
/// around it: see `CodeRecord`.
fn elf_parts(segments: &[Segment], end: usize) -> (Vec<u8>, usize, Vec<u8>) {
    const ET_EXEC: u16 = 2;
    const EM_X86_64: u16 = 62;
    const PT_LOAD: u32 = 1;
    const PF_X_R: u32 = 1 | 4;
    const SHT_PROGBITS: u32 = 1;
    const SHT_SYMTAB: u32 = 2;
    const SHT_STRTAB: u32 = 3;
    const SHF_ALLOC_EXECINSTR: u64 = 2 | 4;
    /// `STB_GLOBAL` and `STT_FUNC`.
    const SYMBOL_INFO: u8 = 1 << 4 | 2;

    let count = segments.len();
    // Section indices: the null section, the segments, `.symtab`, `.strtab`, `.shstrtab`.
    let strtab_index = count.checked_add(2).unwrap();
    let shstrtab_index = count.checked_add(3).unwrap();
    let section_count = count.checked_add(4).unwrap();

    let mut strtab = vec![0];
    let mut symtab = vec![0; SYMBOL_SIZE];
    let mut shstrtab = vec![0];
    let mut section_names = Vec::new();
    for (position, segment) in segments.iter().enumerate() {
        section_names.push(put_string(&mut shstrtab, segment.name));
        let section = u16::try_from(position.checked_add(1).unwrap()).unwrap();
        for symbol in segment.symbols {
            put_u32(&mut symtab, put_string(&mut strtab, &symbol.name));
            symtab.push(SYMBOL_INFO);
            symtab.push(0);
            put_u16(&mut symtab, section);
            put_u64(&mut symtab, symbol.address as u64);
            put_u64(&mut symtab, symbol.size as u64);
        }
    }
    let symtab_name = put_string(&mut shstrtab, ".symtab");
    let strtab_name = put_string(&mut shstrtab, ".strtab");
    let shstrtab_name = put_string(&mut shstrtab, ".shstrtab");

    // Offsets in `tail`, which starts aligned.
    let tail_offset = end.next_multiple_of(8);
    let strtab_offset = symtab.len();
    let shstrtab_offset = strtab_offset.checked_add(strtab.len()).unwrap();
    let section_headers_offset = shstrtab_offset
        .checked_add(shstrtab.len())
        .unwrap()
        .next_multiple_of(8);

    let mut head = Vec::new();
    head.extend_from_slice(&[0x7f, b'E', b'L', b'F', 2, 1, 1, 0]);
    head.extend_from_slice(&[0; 8]);
    put_u16(&mut head, ET_EXEC);
    put_u16(&mut head, EM_X86_64);
    put_u32(&mut head, 1);
    put_u64(&mut head, 0);
    put_u64(&mut head, ELF_HEADER_SIZE as u64);
    put_u64(
        &mut head,
        tail_offset.checked_add(section_headers_offset).unwrap() as u64,
    );
    put_u32(&mut head, 0);
    put_u16(&mut head, ELF_HEADER_SIZE as u16);
    put_u16(&mut head, PROGRAM_HEADER_SIZE as u16);
    put_u16(&mut head, u16::try_from(count).unwrap());
    put_u16(&mut head, SECTION_HEADER_SIZE as u16);
    put_u16(&mut head, u16::try_from(section_count).unwrap());
    put_u16(&mut head, u16::try_from(shstrtab_index).unwrap());
    assert_eq!(head.len(), ELF_HEADER_SIZE);
    for segment in segments {
        let len = segment.len as u64;
        put_u32(&mut head, PT_LOAD);
        put_u32(&mut head, PF_X_R);
        put_u64(&mut head, segment.offset as u64);
        put_u64(&mut head, segment.start as u64);
        put_u64(&mut head, segment.start as u64);
        put_u64(&mut head, len);
        put_u64(&mut head, len);
        put_u64(&mut head, PAGE_ALIGNMENT as u64);
    }

    let mut tail = symtab;
    tail.extend_from_slice(&strtab);
    tail.extend_from_slice(&shstrtab);
    pad_to(&mut tail, section_headers_offset);
    let null_section = SectionHeader {
        name: 0,
        kind: 0,
        flags: 0,
        address: 0,
        offset: 0,
        size: 0,
        link: 0,
        info: 0,
        alignment: 0,
        entry_size: 0,
    };
    put_section_header(&mut tail, &null_section);
    for (position, segment) in segments.iter().enumerate() {
        put_section_header(
            &mut tail,
            &SectionHeader {
                name: section_names[position],
                kind: SHT_PROGBITS,
                flags: SHF_ALLOC_EXECINSTR,
                address: segment.start as u64,
                offset: segment.offset as u64,
                size: segment.len as u64,
                alignment: 16,
                ..null_section
            },
        );
    }
    put_section_header(
        &mut tail,
        &SectionHeader {
            name: symtab_name,
            kind: SHT_SYMTAB,
            offset: tail_offset as u64,
            size: strtab_offset as u64,
            link: strtab_index as u32,
            // The index of the first global symbol, as the null symbol is the only local one.
            info: 1,
            alignment: 8,
            entry_size: SYMBOL_SIZE as u64,
            ..null_section
        },
    );
    put_section_header(
        &mut tail,
        &SectionHeader {
            name: strtab_name,
            kind: SHT_STRTAB,
            offset: tail_offset.checked_add(strtab_offset).unwrap() as u64,
            size: strtab.len() as u64,
            alignment: 1,
            ..null_section
        },
    );
    put_section_header(
        &mut tail,
        &SectionHeader {
            name: shstrtab_name,
            kind: SHT_STRTAB,
            offset: tail_offset.checked_add(shstrtab_offset).unwrap() as u64,
            size: shstrtab.len() as u64,
            alignment: 1,
            ..null_section
        },
    );
    (head, tail_offset, tail)
}

#[cfg(target_os = "linux")]
pub(crate) use linux::CodeRecord;
#[cfg(target_os = "linux")]
pub(super) use linux::{finish_interpreter, finish_jit, finish_supporting_code, map_jit_text};

/// Generating the code into ELF files, and telling debuggers about it.
///
/// Anonymous memory is unnamed to profilers and debuggers. So the code is generated into a shared
/// mapping of an ELF file instead, which `/proc/<pid>/maps` names, and once it is final the file
/// is completed with the symbols, and the code registered with the GDB JIT interface. Either can
/// be off, see `Options`.
#[cfg(target_os = "linux")]
mod linux {
    use super::*;
    use crate::memory_management::{get_system_page_size, PagePermissions};
    use std::fs::File;
    use std::os::fd::AsRawFd as _;
    use std::os::unix::fs::FileExt as _;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::{Mutex, MutexGuard};

    /// What the debugging aids keep of a piece of generated code: the ELF file it is generated
    /// into, and its registration with the GDB JIT interface, if they are on.
    ///
    /// The layout of the file (or of the ELF image registered without one) is that of `elf_parts`
    /// with the one segment: the headers in the first page, the code at the offset of a page,
    /// which is what is mapped, and what `finish` appends after it.
    pub(crate) struct CodeRecord {
        file: Option<(File, PathBuf)>,
        /// The name of the section.
        section: String,
        /// Where the code is, and its length.
        start: usize,
        len: usize,
        registration: Option<Registration>,
    }

    impl CodeRecord {
        /// Start the record of the code of `label`, which is going to be generated into the `len`
        /// bytes at `start`. With `Options::code_dir`, that is a file there mapped over them, so
        /// that what is written there is written to the file.
        ///
        /// # Panics
        ///
        /// If the file cannot be created or mapped, as there is no sensible fallback for a debug
        /// feature that is asked for.
        ///
        /// # Safety
        ///
        /// `start` and `len` must be multiples of the page size, and the range must be pages of
        /// memory that the caller owns, with no content that is still needed, and not accessed
        /// while this runs. The mapping replaces the range, and stays until `release`.
        pub(in crate::codegen) unsafe fn new(label: &str, start: usize, len: usize) -> CodeRecord {
            assert_eq!(get_system_page_size(), PAGE_ALIGNMENT);
            assert!(start.is_multiple_of(PAGE_ALIGNMENT) && len.is_multiple_of(PAGE_ALIGNMENT));
            let section = format!(".text.{label}");
            let Some(directory) = &options().code_dir else {
                return CodeRecord {
                    file: None,
                    section,
                    start,
                    len,
                    registration: None,
                };
            };
            let path = directory.join(format!("sbpf-{}-{label}.elf", std::process::id()));
            let file = std::fs::create_dir_all(directory)
                .and_then(|()| {
                    File::options()
                        .read(true)
                        .write(true)
                        .create(true)
                        .truncate(true)
                        .open(&path)
                })
                .and_then(|file| {
                    file.set_len(PAGE_ALIGNMENT.checked_add(len).unwrap() as u64)?;
                    Ok(file)
                })
                .unwrap_or_else(|error| panic!("failed to create {:?}: {}", path, error));
            // SAFETY:
            //
            // Contract from `mmap` with `MAP_FIXED`: the address must be a multiple of the page
            // size, as must the offset, the file must be open and at least as long as the offset
            // plus the length, and the existing mappings in the range are replaced, so it must
            // be one that the caller owns.
            // Evidence: the address and the length are those of the contract of `new`, the offset
            // is a page, and the file was just made `PAGE_ALIGNMENT + len` bytes long. It is open
            // here, and the mapping outlives the descriptor.
            let mapped = unsafe {
                libc::mmap(
                    start as *mut libc::c_void,
                    len,
                    libc::PROT_READ | libc::PROT_WRITE,
                    libc::MAP_SHARED | libc::MAP_FIXED,
                    file.as_raw_fd(),
                    PAGE_ALIGNMENT as libc::off_t,
                )
            };
            assert!(
                mapped != libc::MAP_FAILED,
                "failed to map {:?}: {}",
                path,
                io::Error::last_os_error()
            );
            CodeRecord {
                file: Some((file, path)),
                section,
                start,
                len,
                registration: None,
            }
        }

        /// Complete the record, once the code is final: the file gets the headers and the
        /// `symbols`, and the code is registered with the GDB JIT interface.
        ///
        /// The writes are not through the mapping, as that only has the code. The mapping is
        /// then replaced with a private one of the same content and the `permissions`, as
        /// debuggers cannot insert breakpoints into shared mappings. So the code must not be
        /// written to afterwards, which the file would not have.
        pub(in crate::codegen) fn finish(
            &mut self,
            symbols: Vec<Symbol>,
            permissions: PagePermissions,
        ) {
            assert!(self.registration.is_none(), "{} is finished", self.section);
            let gdb_jit = options().gdb_jit;
            if self.file.is_none() && !gdb_jit {
                return;
            }
            let segment = Segment {
                name: &self.section,
                start: self.start,
                len: self.len,
                offset: PAGE_ALIGNMENT,
                symbols: &symbols,
            };
            let (head, tail_offset, tail) =
                elf_parts(&[segment], PAGE_ALIGNMENT.checked_add(self.len).unwrap());
            let mut symfile = vec![0; tail_offset.checked_add(tail.len()).unwrap()];
            match &self.file {
                Some((file, path)) => {
                    file.write_all_at(&head, 0)
                        .and_then(|()| file.write_all_at(&tail, tail_offset as u64))
                        .and_then(|()| file.read_exact_at(&mut symfile, 0))
                        .unwrap_or_else(|error| panic!("failed to write {:?}: {}", path, error));
                    let prot = match permissions {
                        PagePermissions::Read => libc::PROT_READ,
                        PagePermissions::ReadWrite => libc::PROT_READ | libc::PROT_WRITE,
                        PagePermissions::ReadExecute => libc::PROT_READ | libc::PROT_EXEC,
                    };
                    // SAFETY:
                    //
                    // Contract from `mmap` with `MAP_FIXED`: as for `new`.
                    // Evidence: the range and the file are those of `new`, whose contract has the
                    // range owned by the caller. The private mapping has the bytes that the shared
                    // one had, as both are of the page cache of the file, so nothing observes a
                    // change, apart from later writes, which the contract of `finish` excludes.
                    let mapped = unsafe {
                        libc::mmap(
                            self.start as *mut libc::c_void,
                            self.len,
                            prot,
                            libc::MAP_PRIVATE | libc::MAP_FIXED,
                            file.as_raw_fd(),
                            PAGE_ALIGNMENT as libc::off_t,
                        )
                    };
                    assert!(
                        mapped != libc::MAP_FAILED,
                        "failed to remap {:?}: {}",
                        path,
                        io::Error::last_os_error()
                    );
                }
                None => {
                    symfile[..head.len()].copy_from_slice(&head);
                    // SAFETY:
                    //
                    // Contract from `read_memory`: the memory must be readable, initialized and
                    // not written to.
                    // Evidence: the contract of `new` has the range owned by the caller, and that
                    // of `finish` has the code final, so nothing writes to it any more.
                    let code = unsafe { read_memory(self.start, self.len) };
                    symfile[PAGE_ALIGNMENT..tail_offset].copy_from_slice(&code);
                    symfile[tail_offset..].copy_from_slice(&tail);
                }
            }
            if gdb_jit {
                self.registration = Some(register(symfile.into_boxed_slice()));
            }
        }

        /// Keep the code known to debuggers for as long as the process lives.
        pub(in crate::codegen) fn keep_forever(mut self) {
            // The entry and the symbol file stay allocated, which the debugger reads.
            std::mem::forget(self.registration.take());
        }

        /// Tell the debuggers that the code is gone, and replace the mapping of the file with
        /// anonymous memory, so that the file stays as it was when the memory is used for
        /// something else.
        ///
        /// # Safety
        ///
        /// The range given to `new` must be memory that the caller still owns, and nothing may
        /// access it while this runs or rely on its content afterwards.
        pub(crate) unsafe fn release(mut self) {
            self.unregister();
            let Some((_, path)) = &self.file else {
                return;
            };
            // SAFETY:
            //
            // Contract from `mmap` with `MAP_FIXED`: the address must be a multiple of the page
            // size, and the mappings in the range are replaced, so it must be one that the caller
            // owns. Without a file the offset must be zero, and the descriptor -1.
            // Evidence: the range is the one `new` checked, and the contract of `release` has it
            // owned by the caller and unused.
            let mapped = unsafe {
                libc::mmap(
                    self.start as *mut libc::c_void,
                    self.len,
                    libc::PROT_READ | libc::PROT_WRITE,
                    libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | libc::MAP_FIXED,
                    -1,
                    0,
                )
            };
            assert!(
                mapped != libc::MAP_FAILED,
                "failed to unmap {:?}: {}",
                path,
                io::Error::last_os_error()
            );
        }

        fn unregister(&mut self) {
            if let Some(registration) = self.registration.take() {
                unregister(registration);
            }
        }
    }

    impl Drop for CodeRecord {
        fn drop(&mut self) {
            // The debugger must not read an entry that is freed.
            self.unregister();
        }
    }

    /// Complete the file of the supporting code, which is final, in pages that are still read-write.
    pub(in crate::codegen) fn finish_supporting_code(
        mut record: CodeRecord,
        supports: &SupportingCode,
    ) {
        record.finish(
            supporting_code_symbols(supports).1,
            PagePermissions::ReadWrite,
        );
        record.keep_forever();
    }

    /// Complete the file of the interpreter at `buffer`, whose steps are final and have the
    /// lengths `step_lens`, in pages that are still read-write.
    pub(in crate::codegen) fn finish_interpreter(
        mut record: CodeRecord,
        version: SBPFVersion,
        buffer: *const u8,
        step_lens: &[u8],
    ) {
        record.finish(
            interpreter_symbols(version, buffer as usize, step_lens),
            PagePermissions::ReadWrite,
        );
        record.keep_forever();
    }

    /// Map a file for the code of the new `program` over its text pages.
    pub(in crate::codegen) fn map_jit_text(program: &mut JitProgram) {
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let text = program.text_section();
        let (start, len) = (text.as_ptr() as usize, text.len());
        let label = format!("jit-{}", COUNTER.fetch_add(1, Ordering::Relaxed));
        // SAFETY:
        //
        // Contract from `CodeRecord::new`: the range must be page aligned, owned by the caller, and
        // not accessed meanwhile, with no content that is needed.
        // Evidence: the text section of a program that is not sealed yet is all of its page
        // rounded text capacity, which starts at a page, after the page rounded pc section, of the
        // allocation. `program` owns it, and nothing was written to it yet. The file is released
        // when the program is dropped, before the allocation is returned to the pool.
        let record = unsafe { CodeRecord::new(&label, start, len) };
        program.code_record = Some(record);
    }

    /// Complete the file of the sealed `program`.
    pub(in crate::codegen) fn finish_jit<const SIZE: usize, C: ContextObject>(
        templates: &JitTemplates<SIZE>,
        executable: &Executable<C>,
        program: &mut JitProgram,
    ) {
        let symbols = jit_symbols(templates, executable, program);
        let file = program
            .code_record
            .as_mut()
            .expect("the program has its file from `map_jit_text`");
        file.finish(symbols, PagePermissions::ReadExecute);
    }

    /// An entry of the list the debugger reads, see `GDB JIT interface` in its documentation.
    #[repr(C)]
    struct JitCodeEntry {
        next: *mut JitCodeEntry,
        prev: *mut JitCodeEntry,
        /// An ELF file in memory.
        symfile_addr: *const u8,
        symfile_size: u64,
    }

    #[repr(C)]
    struct JitDescriptor {
        version: u32,
        action_flag: u32,
        relevant_entry: *mut JitCodeEntry,
        first_entry: *mut JitCodeEntry,
    }

    const JIT_REGISTER_FN: u32 = 1;
    const JIT_UNREGISTER_FN: u32 = 2;

    /// Found by name by the debugger, which reads it when stopped at `__jit_debug_register_code`.
    ///
    /// The unit tests of the crate have their own copy of the crate, besides the one that the
    /// crates it is a dependency of link, so the names would collide there. Only the debugger
    /// cannot see the code of that copy then.
    #[cfg_attr(not(test), no_mangle)]
    #[allow(non_upper_case_globals)]
    static mut __jit_debug_descriptor: JitDescriptor = JitDescriptor {
        version: 1,
        action_flag: 0,
        relevant_entry: std::ptr::null_mut(),
        first_entry: std::ptr::null_mut(),
    };

    /// The debugger has a breakpoint here, to look at what changed in the descriptor.
    #[cfg_attr(not(test), no_mangle)]
    #[inline(never)]
    extern "C" fn __jit_debug_register_code() {
        // SAFETY:
        //
        // Contract from `asm!`: the assembly must be valid, and uphold the options.
        // Evidence: it is empty, and so touches no memory, stack or flags. It is there so that
        // the function is not optimized into nothing, as the debugger needs its address.
        unsafe { std::arch::asm!("", options(nomem, nostack, preserves_flags)) };
    }

    /// Guards the list and the descriptor.
    static LIST_LOCK: Mutex<()> = Mutex::new(());

    fn lock_list() -> MutexGuard<'static, ()> {
        LIST_LOCK.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// An entry in the list, and what it points to.
    struct Registration {
        /// From `Box::into_raw`, and freed after it was removed from the list.
        entry: *mut JitCodeEntry,
        _symfile: Box<[u8]>,
    }

    /// Add the ELF file `symfile` to the list of the debugger.
    fn register(symfile: Box<[u8]>) -> Registration {
        let entry = Box::into_raw(Box::new(JitCodeEntry {
            next: std::ptr::null_mut(),
            prev: std::ptr::null_mut(),
            symfile_addr: symfile.as_ptr(),
            symfile_size: symfile.len() as u64,
        }));
        let _guard = lock_list();
        let descriptor = &raw mut __jit_debug_descriptor;
        // SAFETY:
        //
        // Contract from dereferencing a raw pointer: it must be valid for the reads and writes,
        // and nothing else may access the memory meanwhile.
        // Evidence: `descriptor` is a static, which only this module accesses, and only while
        // holding `LIST_LOCK` (apart from the debugger, which reads it while the process is
        // stopped). `entry` is a fresh allocation. `first` is an entry of the list, as the
        // descriptor only holds entries that `unregister` has not freed yet, which it only does
        // after removing them under the lock.
        unsafe {
            let first = (*descriptor).first_entry;
            (*entry).next = first;
            if !first.is_null() {
                (*first).prev = entry;
            }
            (*descriptor).first_entry = entry;
            (*descriptor).relevant_entry = entry;
            (*descriptor).action_flag = JIT_REGISTER_FN;
        }
        __jit_debug_register_code();
        Registration {
            entry,
            _symfile: symfile,
        }
    }

    /// Remove the `registration` from the list of the debugger.
    fn unregister(registration: Registration) {
        let entry = registration.entry;
        let _guard = lock_list();
        let descriptor = &raw mut __jit_debug_descriptor;
        // SAFETY:
        //
        // Contract from dereferencing a raw pointer: as for `register`.
        // Evidence: as for `register`, with `entry` being in the list as it is only removed here,
        // and so are its neighbours `prev` and `next`, which are updated to skip it.
        unsafe {
            let (prev, next) = ((*entry).prev, (*entry).next);
            if prev.is_null() {
                (*descriptor).first_entry = next;
            } else {
                (*prev).next = next;
            }
            if !next.is_null() {
                (*next).prev = prev;
            }
            (*descriptor).relevant_entry = entry;
            (*descriptor).action_flag = JIT_UNREGISTER_FN;
        }
        __jit_debug_register_code();
        // SAFETY:
        //
        // Contract from `Box::from_raw`: the pointer must come from `Box::into_raw`, and not be
        // freed already.
        // Evidence: `register` made it so, and a `Registration` is consumed here, so it is only
        // freed once. The list no longer has it, and the debugger is done with it, as it was
        // stopped in `__jit_debug_register_code` above until it had read the descriptor.
        drop(unsafe { Box::from_raw(entry) });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn read_u64(bytes: &[u8], offset: usize) -> u64 {
        let mut word = [0; 8];
        word.copy_from_slice(&bytes[offset..offset.checked_add(8).unwrap()]);
        u64::from_le_bytes(word)
    }

    #[test]
    fn supporting_code_symbols() {
        let region = supporting_code();
        let end = region.start + region.bytes.len();
        assert!(region.symbols.iter().any(|s| s.name == "entry_point"));
        assert!(region
            .symbols
            .iter()
            .any(|s| s.name == "divide_div64_r1_r2"));
        assert!(region
            .symbols
            .windows(2)
            .all(|w| w[0].address <= w[1].address));
        for symbol in &region.symbols {
            assert!(symbol.address >= region.start);
            assert!(symbol.address + symbol.size <= end);
        }
        let last = region.symbols.last().unwrap();
        assert_eq!(last.address + last.size, end);
    }

    #[test]
    fn interpreter_symbols_cover_all_steps() {
        const STEP_SIZE: usize = 1 << InterpreterGenerator::STEP_SIZE_LOG2;
        let region = interpreter(SBPFVersion::V3);
        assert_eq!(region.symbols.len(), TemplateOpcode::COUNT);
        assert!(region
            .symbols
            .iter()
            .any(|s| s.name == "step_07_add64_dst0_src0"));
        assert!(region
            .symbols
            .iter()
            .any(|s| s.name == "step_00_op00_dst0_src0"));
        for (index, symbol) in region.symbols.iter().enumerate() {
            let offset = symbol.address - region.start;
            assert_eq!(offset, index * STEP_SIZE);
            assert!(symbol.size > 0 && symbol.size <= STEP_SIZE);
            // The padding traps.
            let padding = &region.bytes[offset + symbol.size..offset + STEP_SIZE];
            assert!(padding.iter().all(|&byte| byte == 0xcc));
        }
    }

    #[test]
    fn template_of_add64_imm() {
        let template = template(SBPFVersion::V3, 0x1207);
        assert!(!template.code.is_empty());
        assert!(!template.relocations.is_empty());
    }

    #[test]
    fn elf_layout() {
        let regions = [
            Region {
                name: ".text.b".to_string(),
                start: 0x20_0010,
                bytes: vec![0x90; 20],
                symbols: vec![Symbol {
                    name: "b".to_string(),
                    address: 0x20_0010,
                    size: 20,
                }],
            },
            Region {
                name: ".text.a".to_string(),
                start: 0x10_0000,
                bytes: vec![0xcc; 4096],
                symbols: Vec::new(),
            },
        ];
        let (elf, offsets) = build_elf(&regions);
        assert_eq!(&elf[..4], b"\x7fELF");
        assert_eq!(offsets[1] % 4096, 0);
        assert_eq!(offsets[0] % 4096, 0x10);
        assert_eq!(&elf[offsets[0]..offsets[0] + 20], &[0x90; 20]);
        // The first segment is the one at the lower address.
        assert_eq!(read_u64(&elf, ELF_HEADER_SIZE + 16), 0x10_0000);
        assert_eq!(
            read_u64(&elf, ELF_HEADER_SIZE + PROGRAM_HEADER_SIZE + 16),
            0x20_0010
        );
    }
}

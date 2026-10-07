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
//! - `SBPF_DEBUG_GDB_INTEGRATION` (Linux, on unless `0`, `false`, `off` or `no`): once the code is
//!   final, it is registered with the GDB JIT interface, so that `gdb` resolves the symbols without
//!   being told about any files.
//! - `SBPF_DEBUG_INSTRUCTION_SYMBOLS` (off unless `1`, `true`, `on` or `yes`): the JIT output has a
//!   symbol for each BPF instruction, rather than only for the functions of the executable, which
//!   is expensive for large programs.

use super::arch::SupportingCode;
use super::generate::{self, InterpreterGenerator};
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
    /// `SBPF_DEBUG_INSTRUCTION_SYMBOLS`.
    pub instruction_symbols: bool,
}

/// The `Options` of the process, read from the environment once, before anything is generated.
pub fn options() -> &'static Options {
    static OPTIONS: std::sync::LazyLock<Options> = std::sync::LazyLock::new(|| Options {
        stack_checks: env_flag("SBPF_DEBUG_STACK_CHECKS", true),
        code_dir: std::env::var_os("SBPF_DEBUG_CODE_DIR").map(std::path::PathBuf::from),
        gdb_jit: env_flag("SBPF_DEBUG_GDB_INTEGRATION", true),
        instruction_symbols: env_flag("SBPF_DEBUG_INSTRUCTION_SYMBOLS", false),
    });
    &OPTIONS
}

/// Whether the environment variable `name` turns its debugging aid on, or `default` if it is not
/// set.
///
/// # Panics
///
/// If the value is not one of the recognized ones, rather than guessing what was meant.
fn env_flag(name: &str, default: bool) -> bool {
    let Some(value) = std::env::var_os(name) else {
        return default;
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
    let interpreter = generate::interpreter(version);
    let start = interpreter.buffer as usize;
    // SAFETY:
    //
    // Contract from `read_memory`: `start` must be non-null, and the `len` bytes at it must be
    // readable and initialized, within a single allocation.
    //
    // Contract from `read_memory`: Nothing may write to these bytes while this runs.
    //
    // Evidence: `buffer` is the allocation of `allocate_pages_low` of `STEP_TABLE_SIZE` bytes that
    // `generate::interpreter` generated in full, so non-null and initialized, which is
    // read-execute and never written to or freed afterwards.
    let bytes = unsafe { read_memory(start, InterpreterGenerator::STEP_TABLE_SIZE) };
    Region {
        name: format!(".text.interpreter_{}", version_name(version)),
        start,
        bytes,
        symbols: interpreter_symbols(version, start, &interpreter.step_lens),
    }
}

/// The JIT output `program` of `executable`, with a symbol per function of the executable, or per
/// BPF instruction with `instruction_symbols`.
///
/// # Panics
///
/// If `program` was not produced by `codegen`.
pub fn jit<C: ContextObject>(
    executable: &Executable<C>,
    program: &JitProgram,
    instruction_symbols: bool,
) -> Region {
    assert!(program.dynasm, "not a program of codegen");
    let templates = generate::jit_templates(executable.get_sbpf_version());
    let text = program.text_section();
    Region {
        name: ".text.jit".to_string(),
        start: text.as_ptr() as usize,
        bytes: text.to_vec(),
        symbols: jit_symbols(templates, executable, program, instruction_symbols),
    }
}

/// The JIT template for the instructions with the `TemplateOpcode` `opcode`: the opcode of the
/// instruction in bits 0 to 7, the destination register in 8 to 11 and the source register in 12
/// to 15.
///
/// # Panics
///
/// If `codegen` does not support `version`.
pub fn template(version: SBPFVersion, opcode: u16) -> Template {
    let templates = generate::jit_templates(version);
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
    std::fs::write(path, elf_image(regions))
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
/// - `start` must be non-null, and the `len` bytes at it must be readable and initialized, within
///   a single allocation.
/// - Nothing may mutate the pointee while this runs.
unsafe fn read_memory(start: usize, len: usize) -> Vec<u8> {
    // SAFETY:
    //
    // Contract from `slice::from_raw_parts`: `data` must be non-null, valid for reads for `len *
    // size_of::<T>()` many bytes, and it must be properly aligned. This means in particular: The
    // entire memory range of this slice must be contained within a single allocation! Slices can
    // never span across multiple allocations.
    //
    // Contract from `slice::from_raw_parts`: `data` must point to `len` consecutive properly
    // initialized values of type `T`.
    //
    // Contract from `slice::from_raw_parts`: The memory referenced by the returned slice must not
    // be mutated for the duration of lifetime `'a`, except inside an `UnsafeCell`.
    //
    // Contract from `slice::from_raw_parts`: The total size `len * size_of::<T>()` of the slice
    // must be no larger than `isize::MAX`, and adding that size to `data` must not "wrap around"
    // the address space. See the safety documentation of `pointer::offset`.
    //
    // Evidence: `T` is `u8`, so the pointer is aligned. The rest is delegated to the callers of
    // this function.
    unsafe { std::slice::from_raw_parts(start as *const u8, len) }.to_vec()
}

fn supporting_code_region(supports: &SupportingCode) -> Region {
    let (range, symbols) = supporting_code_symbols(supports);
    // SAFETY:
    //
    // Contract from `read_memory`: `start` must be non-null, and the `len` bytes at it must be
    // readable and initialized, within a single allocation.
    //
    // Contract from `read_memory`: Nothing may write to these bytes while this runs.
    //
    // Evidence: the range is the code that `SupportingCode` generated at the start of its
    // allocation of `allocate_pages_low`, so non-null and initialized, which is read-execute and
    // never written to or freed afterwards.
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

/// The symbols of the sealed `program`: one per function of the executable (or per BPF instruction
/// with `instruction_symbols`), and the templates around them.
fn jit_symbols<const SIZE: usize, C: ContextObject>(
    templates: &JitTemplates<SIZE>,
    executable: &Executable<C>,
    program: &JitProgram,
    instruction_symbols: bool,
) -> Vec<Symbol> {
    let text = program.text_section();
    let start = text.as_ptr() as usize;

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
    let pc_section = program.pc_section();
    if instruction_symbols {
        let version = executable.get_sbpf_version();
        let bpf = executable.get_text_bytes().1;
        let loader = BuiltinProgram::<DummyContextObject>::new_mock();
        for (pc, &offset) in pc_section.iter().enumerate() {
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
    } else {
        let mut functions = BTreeMap::new();
        for (_, (name, pc)) in executable.get_function_registry().iter() {
            functions.insert(pc, String::from_utf8_lossy(name).into_owned());
        }
        functions
            .entry(executable.get_entrypoint_instruction_offset())
            .or_insert_with(|| "entrypoint".to_string());
        for (pc, name) in functions {
            // Ignore what the verifier would reject.
            let Some(&offset) = pc_section.get(pc) else {
                continue;
            };
            if offset == JitTemplates::<SIZE>::INVALID_CALL_TARGET {
                continue;
            }
            let name = if name.is_empty() {
                format!("function_{pc}")
            } else {
                name
            };
            named.push((name, start.checked_add(offset as usize).unwrap()));
        }
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

/// An ELF executable with the `regions`, each of which is a section and a `PT_LOAD` segment at
/// its address, at a file offset congruent to the address modulo the page size so that the file
/// can be mapped at it. The symbols of the regions are in `.symtab`.
fn elf_image(regions: &[Region]) -> Vec<u8> {
    use object::elf;
    use object::write::elf::{FileHeader, ProgramHeader, SectionHeader, Sym, Writer};

    // The segments have to be in the order of their addresses.
    let mut regions: Vec<&Region> = regions.iter().collect();
    regions.sort_by_key(|region| region.start);
    let mut image = Vec::new();
    let mut writer = Writer::new(object::Endianness::Little, true, &mut image);

    // Everything is reserved first, then written in the same order.
    writer.reserve_file_header();
    writer.reserve_program_headers(u32::try_from(regions.len()).unwrap());
    let mut offsets = Vec::with_capacity(regions.len());
    for region in &regions {
        let page = usize::try_from(writer.reserved_len())
            .unwrap()
            .next_multiple_of(PAGE_ALIGNMENT);
        let offset = page.checked_add(region.start % PAGE_ALIGNMENT).unwrap();
        writer.reserve_until(offset as u64);
        writer.reserve(region.bytes.len() as u64, 1);
        offsets.push(offset);
    }
    writer.reserve_null_section_index();
    let sections: Vec<_> = regions
        .iter()
        .map(|region| {
            let name = writer.add_section_name(region.name.as_bytes());
            (name, writer.reserve_section_index())
        })
        .collect();
    writer.reserve_symtab_section_index();
    writer.reserve_strtab_section_index();
    writer.reserve_shstrtab_section_index();
    writer.reserve_null_symbol_index();
    let mut symbols = Vec::new();
    for (region, &(_, section)) in regions.iter().zip(&sections) {
        for symbol in &region.symbols {
            writer.reserve_symbol_index(Some(section));
            symbols.push((writer.add_string(symbol.name.as_bytes()), section, symbol));
        }
    }
    writer.reserve_symtab();
    writer.reserve_strtab().unwrap();
    writer.reserve_shstrtab().unwrap();
    writer.reserve_section_headers();

    writer
        .write_file_header(&FileHeader {
            os_abi: elf::ELFOSABI_NONE,
            abi_version: 0,
            e_type: elf::ET_EXEC,
            e_machine: elf::EM_X86_64,
            e_entry: 0,
            e_flags: Default::default(),
        })
        .unwrap();
    writer.write_align_program_headers();
    for (region, &offset) in regions.iter().zip(&offsets) {
        writer.write_program_header(&ProgramHeader {
            p_type: elf::PT_LOAD,
            p_flags: elf::PF_R | elf::PF_X,
            p_offset: offset as u64,
            p_vaddr: region.start as u64,
            p_paddr: region.start as u64,
            p_filesz: region.bytes.len() as u64,
            p_memsz: region.bytes.len() as u64,
            p_align: PAGE_ALIGNMENT as u64,
        });
    }
    for (region, &offset) in regions.iter().zip(&offsets) {
        writer.pad_until(offset as u64);
        writer.write(&region.bytes);
    }
    writer.write_null_symbol();
    for &(name, section, symbol) in &symbols {
        writer.write_symbol(&Sym {
            section: Some(section.0),
            st_name: writer.string_offset(Some(name)),
            st_info: elf::SymbolInfo::new(elf::STB_GLOBAL, elf::STT_FUNC),
            st_other: Default::default(),
            st_shndx: Default::default(),
            st_value: symbol.address as u64,
            st_size: symbol.size as u64,
        });
    }
    writer.write_strtab();
    writer.write_shstrtab();
    writer.write_null_section_header();
    for (region, (&(name, _), &offset)) in regions.iter().zip(sections.iter().zip(&offsets)) {
        writer.write_section_header(&SectionHeader {
            sh_name: writer.section_name_offset(Some(name)),
            sh_type: elf::SHT_PROGBITS,
            sh_flags: elf::SHF_ALLOC | elf::SHF_EXECINSTR,
            sh_addr: region.start as u64,
            sh_offset: offset as u64,
            sh_size: region.bytes.len() as u64,
            sh_link: 0,
            sh_info: 0,
            sh_addralign: 16,
            sh_entsize: 0,
        });
    }
    // The null symbol is the only local one.
    writer.write_symtab_section_header(1);
    writer.write_strtab_section_header();
    writer.write_shstrtab_section_header();
    image
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
    /// The file (or the ELF image registered without one) is the `elf_image` of the one region:
    /// the headers in the first page, the code at the offset of a page, which is what is mapped,
    /// and what `finish` writes after it.
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
        /// - The `len` bytes at `start` must be pages of a mapping that the caller owns.
        /// - Nothing may access these pages while this runs, or rely on what they held before:
        ///   they are replaced with a mapping that stays until `release`.
        pub(in crate::codegen) unsafe fn new(label: &str, start: usize, len: usize) -> CodeRecord {
            // SAFETY:
            //
            // Contract from `CodeRecord::new_in`: The `len` bytes at `start` must be pages of a
            // mapping that the caller owns.
            //
            // Contract from `CodeRecord::new_in`: Nothing may access these pages while this runs,
            // or rely on what they held before: they are replaced with a mapping that stays until
            // `release`.
            //
            // Evidence: the same contract as this function's.
            unsafe { Self::new_in(options().code_dir.as_deref(), label, start, len) }
        }

        /// `new`, with the file in `code_dir` rather than in `Options::code_dir`.
        ///
        /// # Safety
        ///
        /// - The `len` bytes at `start` must be pages of a mapping that the caller owns.
        /// - Nothing may access these pages while this runs, or rely on what they held before:
        ///   they are replaced with a mapping that stays until `release`.
        pub(super) unsafe fn new_in(
            code_dir: Option<&Path>,
            label: &str,
            start: usize,
            len: usize,
        ) -> CodeRecord {
            assert_eq!(get_system_page_size(), PAGE_ALIGNMENT);
            assert!(start.is_multiple_of(PAGE_ALIGNMENT) && len.is_multiple_of(PAGE_ALIGNMENT));
            let section = format!(".text.{label}");
            let Some(directory) = code_dir else {
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
            // Contract from calling `libc::mmap`: none documented. As for any foreign function, the
            // effects must not be undefined behavior in Rust, such as r[undefined.pointer-access]
            // of the Reference: Accessing (loading from or storing to) a place that is dangling or
            // based on a misaligned pointer.
            //
            // Behaviour from `mmap(2)`: MAP_FIXED Don't interpret addr as a hint: place the mapping
            // at exactly that address. addr must be suitably aligned: for most architectures a
            // multiple of the page size is sufficient; however, some architectures may impose
            // additional restrictions. If the memory region specified by addr and length overlaps
            // pages of any existing mapping(s), then the overlapped part of the existing mapping(s)
            // will be discarded. If the specified address cannot be used, mmap() will fail.
            //
            // Evidence: the part of the existing mappings that is discarded is the `len` bytes at
            // `start`, which the contract of `new_in` has be pages of a mapping that the caller owns,
            // which nothing accesses while this runs, or relies on the content of. Accesses
            // afterwards are to the new mapping, which is read-write like the memory it replaces.
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
        /// The mapping is then replaced with a private one of the same content and the
        /// `permissions`, as debuggers cannot insert breakpoints into shared mappings. So the code
        /// must not be written to afterwards, which the file would not have.
        pub(in crate::codegen) fn finish(
            &mut self,
            symbols: impl FnOnce() -> Vec<Symbol>,
            permissions: PagePermissions,
        ) {
            assert!(self.registration.is_none(), "{} is finished", self.section);
            let gdb_jit = options().gdb_jit;
            if self.file.is_none() && !gdb_jit {
                return;
            }
            // SAFETY:
            //
            // Contract from `read_memory`: `start` must be non-null, and the `len` bytes at it must
            // be readable and initialized, within a single allocation.
            //
            // Contract from `read_memory`: Nothing may write to these bytes while this runs.
            //
            // Evidence: the range is the one given to `new_in`, which the contract of `new_in` has
            // be pages of a mapping that the caller owns, so non-null and readable, and
            // initialized as mapped memory is. The code is final when `finish` is called, and
            // nothing writes to it meanwhile: the records of the supporting code and of the
            // interpreters are finished while they are generated, and that of a `JitProgram` once
            // it is sealed but before `compile` returns it, through `&mut`.
            let code = unsafe { read_memory(self.start, self.len) };
            let image = elf_image(&[Region {
                name: self.section.clone(),
                start: self.start,
                bytes: code,
                symbols: symbols(),
            }]);
            // Where the file is mapped.
            assert!(image
                .get(PAGE_ALIGNMENT..)
                .is_some_and(|code| code.len() >= self.len));
            if let Some((file, path)) = &self.file {
                // The code in the file is what is written there, as it is mapped there.
                file.write_all_at(&image, 0)
                    .unwrap_or_else(|error| panic!("failed to write {:?}: {}", path, error));
                let prot = match permissions {
                    PagePermissions::Read => libc::PROT_READ,
                    PagePermissions::ReadWrite => libc::PROT_READ | libc::PROT_WRITE,
                    PagePermissions::ReadExecute => libc::PROT_READ | libc::PROT_EXEC,
                };
                // SAFETY:
                //
                // Contract from calling `libc::mmap`: none documented. As for any foreign
                // function, the effects must not be undefined behavior in Rust, such as
                // r[undefined.pointer-access] of the Reference: Accessing (loading from or
                // storing to) a place that is dangling or based on a misaligned pointer.
                //
                // Behaviour from `mmap(2)`: MAP_FIXED Don't interpret addr as a hint: place the
                // mapping at exactly that address. addr must be suitably aligned: for most
                // architectures a multiple of the page size is sufficient; however, some
                // architectures may impose additional restrictions. If the memory region
                // specified by addr and length overlaps pages of any existing mapping(s), then
                // the overlapped part of the existing mapping(s) will be discarded. If the
                // specified address cannot be used, mmap() will fail.
                //
                // Evidence: the part of the existing mappings that is discarded is the mapping
                // of the file that `new_in` made, which the contract of `new_in` has be the
                // record's until `release`. Nothing accesses it meanwhile: the records of the
                // supporting code and of the interpreters are finished while they are generated,
                // and that of a `JitProgram` once it is sealed but before `compile` returns it,
                // through `&mut`. Accesses afterwards are to the new mapping, with the bytes of
                // the file, which are those of the code, and the `permissions` that the code
                // needs.
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
            if gdb_jit {
                self.registration = Some(register(image.into_boxed_slice()));
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
        /// - The `len` bytes at `start` given to `new` must still be pages that the caller owns.
        /// - Nothing may access these pages while this runs, or rely on what they held before:
        ///   they are replaced with an anonymous mapping.
        pub(crate) unsafe fn release(mut self) {
            self.unregister();
            let Some((_, path)) = &self.file else {
                return;
            };
            // SAFETY:
            //
            // Contract from calling `libc::mmap`: none documented. As for any foreign function, the
            // effects must not be undefined behavior in Rust, such as r[undefined.pointer-access]
            // of the Reference: Accessing (loading from or storing to) a place that is dangling or
            // based on a misaligned pointer.
            //
            // Behaviour from `mmap(2)`: MAP_FIXED Don't interpret addr as a hint: place the mapping
            // at exactly that address. addr must be suitably aligned: for most architectures a
            // multiple of the page size is sufficient; however, some architectures may impose
            // additional restrictions. If the memory region specified by addr and length overlaps
            // pages of any existing mapping(s), then the overlapped part of the existing mapping(s)
            // will be discarded. If the specified address cannot be used, mmap() will fail.
            //
            // Evidence: the part of the existing mappings that is discarded is the `len` bytes at
            // `start`, which the contract of `release` has still be pages that the caller owns,
            // which nothing accesses while this runs, or relies on the content of afterwards.
            // Accesses afterwards are to the new mapping, which is read-write like the memory of
            // the pool that it returns to.
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
            || supporting_code_symbols(supports).1,
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
            || interpreter_symbols(version, buffer as usize, step_lens),
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
        // Contract from `CodeRecord::new`: The `len` bytes at `start` must be pages of a mapping
        // that the caller owns.
        //
        // Contract from `CodeRecord::new`: Nothing may access these pages while this runs, or rely
        // on what they held before: they are replaced with a mapping that stays until `release`.
        //
        // Evidence: the text section of a program that is not sealed is all of its page-rounded
        // text capacity, which starts at a page boundary after the page-rounded pc section, within
        // the allocation that `program` owns. Nothing was written to it yet, and the code is
        // generated into it afterwards. The `JitProgram` releases the record when dropped, before
        // returning the allocation to the pool.
        let record = unsafe { CodeRecord::new(&label, start, len) };
        program.code_record = Some(record);
    }

    /// Complete the file of the sealed `program`.
    pub(in crate::codegen) fn finish_jit<const SIZE: usize, C: ContextObject>(
        templates: &JitTemplates<SIZE>,
        executable: &Executable<C>,
        program: &mut JitProgram,
    ) {
        let mut record = program
            .code_record
            .take()
            .expect("the program has its file from `map_jit_text`");
        record.finish(
            || {
                jit_symbols(
                    templates,
                    executable,
                    program,
                    options().instruction_symbols,
                )
            },
            PagePermissions::ReadExecute,
        );
        program.code_record = Some(record);
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
        // Contract from `asm!`: r[asm.rules.reg-not-output]: Any registers not specified as outputs
        // must have the same value upon exiting the assembly code as they had on entry, otherwise
        // behavior is undefined.
        //
        // Contract from `asm!`: r[asm.rules.unwind]: Behavior is undefined if execution unwinds out
        // of the assembly code. This also applies if the assembly code calls a function which then
        // unwinds.
        //
        // Contract from `asm!`: r[asm.rules.mem-same-as-ffi]: The set of memory locations that
        // assembly code is allowed to read and write are the same as those allowed for an FFI
        // function. If the `readonly` option is set, then only memory reads are allowed. If the
        // `nomem` option is set then no reads or writes to memory are allowed.
        //
        // Contract from `asm!`: r[asm.rules.preserved-registers]: These flags registers must be
        // restored upon exiting the assembly code if the `preserves_flags` option is set: Status
        // flags in `EFLAGS` (CF, PF, AF, ZF, SF, OF). Floating-point status word (all).
        // Floating-point exception flags in `MXCSR` (PE, UE, OE, ZE, DE, IE).
        //
        // Contract from `asm!`: r[asm.rules.x86-df]: On x86, the direction flag (DF in `EFLAGS`) is
        // clear on entry to the assembly code and must be clear on exit.
        //
        // Contract from `asm!`: r[asm.rules.x86-x87]: On x86, the x87 floating-point register stack
        // must remain unchanged unless all of the `st([0-7])` registers have been marked as
        // clobbered with `out("st(0)") _, out("st(1)") _, ...`.
        //
        // Contract from `asm!`: r[asm.rules.x86-prefix-restriction]: On x86, inline assembly must
        // not end with an instruction prefix (such as `LOCK`) that would apply to instructions
        // generated by the compiler.
        //
        // Evidence: the assembly code is empty, so it changes no registers or flags, calls nothing,
        // and accesses no memory or stack. It is there so that the function is not optimized into
        // nothing, as the debugger needs its address.
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
        // Contract from `dereferencing a raw pointer (the Reference)`: r[undefined.race]: Data
        // races.
        //
        // Contract from `dereferencing a raw pointer (the Reference)`: r[undefined.pointer-access]:
        // Accessing (loading from or storing to) a place that is dangling or based on a misaligned
        // pointer.
        //
        // Contract from `dereferencing a raw pointer (the Reference)`: r[undefined.alias]: Breaking
        // the pointer aliasing rules.
        //
        // Evidence: `descriptor` points to a static, which lives forever and is aligned, and
        // `entry` to a fresh `Box` allocation of a `JitCodeEntry`. `first` is an entry in the list,
        // as the list only holds entries that `unregister` has not freed yet, which it frees after
        // removing them. Only this module accesses the static and the entries, while holding
        // `LIST_LOCK` (apart from the debugger, which reads them while the process is stopped), so
        // there is no data race. They are only accessed through raw pointers, so no reference to
        // them is live.
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
        // Contract from `dereferencing a raw pointer (the Reference)`: r[undefined.race]: Data
        // races.
        //
        // Contract from `dereferencing a raw pointer (the Reference)`: r[undefined.pointer-access]:
        // Accessing (loading from or storing to) a place that is dangling or based on a misaligned
        // pointer.
        //
        // Contract from `dereferencing a raw pointer (the Reference)`: r[undefined.alias]: Breaking
        // the pointer aliasing rules.
        //
        // Evidence: as for `register`, with `entry` in the list, as it is only removed here, and so
        // its neighbours `prev` and `next`, which are updated to skip it.
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
        // Contract from `Box::from_raw`: The raw pointer must point to a block of memory allocated
        // by the global allocator.
        //
        // Contract from `std::boxed`: More precisely, a `value: *mut T` that has been allocated
        // with the `Global` allocator with `Layout::for_value(&*value)` may be converted into a box
        // using `Box::<T>::from_raw(value)`.
        //
        // Contract from `std::boxed`: On top of these basic layout requirements, a `Box<T>` must
        // point to a valid value of `T`.
        //
        // Evidence: `register` made `entry` with `Box::into_raw(Box::new(..))`, so it was allocated
        // by the global allocator with the layout of a `JitCodeEntry`, and points to a valid one. A
        // `Registration` is consumed here, so the entry is only freed once. The list no longer has
        // it, and the debugger is done with it, as it was stopped in `__jit_debug_register_code`
        // above until it had read the descriptor.
        drop(unsafe { Box::from_raw(entry) });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use object::read::elf::{ElfFile64, ProgramHeader as _};
    use object::{Object as _, ObjectSection as _, ObjectSymbol as _};

    /// Check that `image` has the `regions`, as `elf_image` lays them out.
    fn check_elf_image(image: &[u8], regions: &[Region]) {
        let file = ElfFile64::<object::Endianness>::parse(image).unwrap();
        let endian = file.endian();
        let mut by_address: Vec<_> = regions.iter().collect();
        by_address.sort_by_key(|region| region.start);
        let segments = file.elf_program_headers();
        assert_eq!(segments.len(), regions.len());
        for (segment, region) in segments.iter().zip(by_address) {
            assert_eq!(segment.p_vaddr(endian), region.start as u64);
            // So that the file can be mapped at the address.
            let in_page = (PAGE_ALIGNMENT as u64).checked_sub(1).unwrap();
            assert_eq!(
                segment.p_offset(endian) & in_page,
                region.start as u64 & in_page
            );
            assert_eq!(segment.data(endian, image).unwrap(), region.bytes);
        }
        for region in regions {
            let section = file.section_by_name(&region.name).unwrap();
            assert_eq!(section.address(), region.start as u64);
            assert_eq!(section.data().unwrap(), region.bytes);
            for symbol in &region.symbols {
                let found = file
                    .symbols()
                    .find(|found| found.name() == Ok(symbol.name.as_str()))
                    .unwrap();
                assert_eq!(found.address(), symbol.address as u64);
                assert_eq!(found.size(), symbol.size as u64);
                assert_eq!(found.section_index(), Some(section.index()));
                assert_eq!(found.kind(), object::SymbolKind::Text);
                assert!(found.is_global());
            }
        }
        let symbol_count: usize = regions.iter().map(|region| region.symbols.len()).sum();
        assert_eq!(file.symbols().count(), symbol_count);
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

    /// Regions out of the order of their addresses, and one not at the start of a page.
    #[test]
    fn elf_image_layout() {
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
                symbols: sized_symbols(
                    vec![("a2".to_string(), 0x10_0010), ("a1".to_string(), 0x10_0000)],
                    0x10_1000,
                ),
            },
            Region {
                name: ".text.empty".to_string(),
                start: 0x30_0000,
                bytes: Vec::new(),
                symbols: Vec::new(),
            },
        ];
        check_elf_image(&elf_image(&regions), &regions);
    }

    #[test]
    fn jit_symbols_of_functions_or_instructions() {
        use crate::vm::Config;
        use std::sync::Arc;
        let loader = Arc::new(BuiltinProgram::<DummyContextObject>::new_loader(
            Config::default(),
        ));
        let executable = crate::assembler::assemble(
            "
            call function_foo
            lddw r0, 1
            exit
            function_foo:
            mov64 r0, 0
            exit",
            loader,
        )
        .unwrap();
        executable.dynasm_compile().unwrap();
        let program = executable.get_compiled_program().unwrap();
        for (instruction_symbols, expected) in [
            (false, &["entrypoint", "function_foo"][..]),
            (
                true,
                &[
                    "pc_0_call",
                    "pc_1_lddw",
                    "pc_3_exit",
                    "pc_4_mov64",
                    "pc_5_exit",
                ][..],
            ),
        ] {
            let region = jit(&executable, &program, instruction_symbols);
            let names: Vec<_> = region.symbols.iter().map(|s| s.name.as_str()).collect();
            let shared = [
                "invalid_call_target",
                "sig_invalid_insn",
                "sig_meter_exceeded",
            ];
            assert_eq!(names[..3], shared);
            assert_eq!(names[3..names.len() - 1], *expected);
            assert_eq!(names.last(), Some(&"execution_overrun"));
            let end = region.start + region.bytes.len();
            assert!(region
                .symbols
                .windows(2)
                .all(|w| w[0].address + w[0].size <= w[1].address));
            assert_eq!(
                region.symbols.last().unwrap().address + region.symbols.last().unwrap().size,
                end
            );
            let regions = std::slice::from_ref(&region);
            check_elf_image(&elf_image(regions), regions);
        }
    }

    /// The code is generated into a file mapped over it, which keeps the code once the mapping
    /// is replaced, and the file what it had once the memory is released.
    #[cfg(target_os = "linux")]
    #[test]
    fn code_record_file() {
        use crate::memory_management::{allocate_pages_low, PagePermissions};
        let directory =
            std::env::temp_dir().join(format!("sbpf-code-record-{}", std::process::id()));
        let label = "code-record-test";
        // Leaked, as the pages are only freed by the owners of the code that this is the record of.
        let start = allocate_pages_low(PAGE_ALIGNMENT).unwrap() as usize;
        // SAFETY:
        //
        // Contract from `CodeRecord::new_in`: The `len` bytes at `start` must be pages of a
        // mapping that the caller owns.
        //
        // Contract from `CodeRecord::new_in`: Nothing may access these pages while this runs, or
        // rely on what they held before: they are replaced with a mapping that stays until
        // `release`.
        //
        // Evidence: the page was just allocated by `allocate_pages_low` for this test, which
        // nothing else knows of, and it is only accessed afterwards.
        let mut record =
            unsafe { CodeRecord::new_in(Some(&directory), label, start, PAGE_ALIGNMENT) };
        let code = [0x90, 0xc3];
        // SAFETY:
        //
        // Contract from `ptr::copy_nonoverlapping`: `src` must be valid for reads of `count *
        // size_of::<T>()` bytes or that number must be 0.
        //
        // Contract from `ptr::copy_nonoverlapping`: `dst` must be valid for writes of `count *
        // size_of::<T>()` bytes or that number must be 0.
        //
        // Contract from `ptr::copy_nonoverlapping`: Both `src` and `dst` must be properly aligned.
        //
        // Contract from `ptr::copy_nonoverlapping`: The region of memory beginning at `src` with a
        // size of `count * size_of::<T>()` bytes must *not* overlap with the region of memory
        // beginning at `dst` with the same size.
        //
        // Evidence: `T` is `u8`, so the pointers are aligned, and the size is 2 bytes. `code` is
        // an array, so valid for reads, and the destination is the start of the read-write
        // mapping of the file that `new_in` made, which does not overlap it.
        unsafe { std::ptr::copy_nonoverlapping(code.as_ptr(), start as *mut u8, code.len()) };
        let symbol = Symbol {
            name: "f".to_string(),
            address: start,
            size: code.len(),
        };
        let symbols = vec![symbol.clone()];
        record.finish(|| symbols, PagePermissions::ReadExecute);
        // SAFETY:
        //
        // Contract from `read_memory`: `start` must be non-null, and the `len` bytes at it must be
        // readable and initialized, within a single allocation.
        //
        // Contract from `read_memory`: Nothing may write to these bytes while this runs.
        //
        // Evidence: `finish` mapped the page read-execute with the content of the file, and
        // nothing else knows of it.
        let mapped = unsafe { read_memory(start, PAGE_ALIGNMENT) };
        let mut expected = vec![0; PAGE_ALIGNMENT];
        expected[..code.len()].copy_from_slice(&code);
        assert_eq!(mapped, expected);
        let path = directory.join(format!("sbpf-{}-{label}.elf", std::process::id()));
        let image = std::fs::read(&path).unwrap();
        let region = Region {
            name: format!(".text.{label}"),
            start,
            bytes: expected,
            symbols: vec![symbol],
        };
        check_elf_image(&image, &[region]);
        // SAFETY:
        //
        // Contract from `CodeRecord::release`: The `len` bytes at `start` given to `new` must
        // still be pages that the caller owns.
        //
        // Contract from `CodeRecord::release`: Nothing may access these pages while this runs, or
        // rely on what they held before: they are replaced with an anonymous mapping.
        //
        // Evidence: the page is still this test's, and it is not accessed afterwards.
        unsafe { record.release() };
        assert_eq!(std::fs::read(&path).unwrap(), image);
        std::fs::remove_dir_all(&directory).unwrap();
    }
}

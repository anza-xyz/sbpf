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
//! - `SBPF_DEBUG_CODE_DIR` (off unless set and not empty): the running code itself is generated
//!   into ELF files in that directory, so that the tools know its symbols in the running process:
//!   the supporting code, each interpreter and each JIT program (its code and its pc section) are
//!   generated into a private mapping of `sbpf-<pid>-<label>.elf`, with `<label>` being
//!   `supports`, `interpreter-<version>` or `jit-<n>`, which gets the ELF headers and the symbols
//!   once the code is final, see `DebugImage`. The directory must allow executable mappings (not
//!   `noexec`). `/proc/<pid>/maps` names the files on Linux. Those of the JIT programs stay on disk
//!   after the programs are dropped, as the record of them. Untested on Windows, which maps the
//!   files too.
//! - `SBPF_DEBUG_GDB_INTEGRATION` (on unless `0`, `false`, `off` or `no`): once the code is
//!   final, it is registered with the GDB JIT interface, so that `gdb` resolves the symbols without
//!   being told about any files.
//! - `SBPF_DEBUG_INSTRUCTION_SYMBOLS` (off unless `1`, `true`, `on` or `yes`): the JIT output has a
//!   symbol for each BPF instruction, rather than only for the functions of the executable, which
//!   is expensive for large programs.

use super::arch::SupportingCode;
use super::generate::{self, Interpreter, InterpreterGenerator};
use super::{AuxTemplate, JitTemplates, TemplateOpcode};
use crate::disassembler::disassemble_instruction;
use crate::ebpf;
use crate::elf::Executable;
use crate::error::EbpfError;
use crate::memory_management::{get_system_page_size, round_to_page_size, Mapping, MappingBuilder};
use crate::program::{BuiltinProgram, FunctionRegistry, JitProgram, SBPFVersion};
use crate::static_analysis::DummyContextObject;
use crate::vm::ContextObject;
use std::collections::BTreeMap;
use std::convert::TryFrom;
use std::fmt;
use std::fs::File;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, MutexGuard};

/// Which of the debugging aids are on, see the module documentation.
#[derive(Clone, Debug)]
pub struct Options {
    /// `SBPF_DEBUG_STACK_CHECKS`.
    pub stack_checks: bool,
    /// `SBPF_DEBUG_CODE_DIR`, the directory to generate the code into files in.
    pub code_dir: Option<PathBuf>,
    /// `SBPF_DEBUG_GDB_INTEGRATION`.
    pub gdb_jit: bool,
    /// `SBPF_DEBUG_INSTRUCTION_SYMBOLS`.
    pub instruction_symbols: bool,
}

/// The `Options` of the process, read from the environment once, before anything is generated.
pub fn options() -> &'static Options {
    static OPTIONS: std::sync::LazyLock<Options> = std::sync::LazyLock::new(|| Options {
        stack_checks: env_flag("SBPF_DEBUG_STACK_CHECKS", true),
        code_dir: std::env::var_os("SBPF_DEBUG_CODE_DIR")
            .filter(|dir| !dir.is_empty())
            .map(PathBuf::from),
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

/// A contiguous piece of generated code, or of the data it reads.
#[derive(Clone, Debug)]
pub struct Region {
    /// Name of the ELF section, e.g. `.text.jit`.
    pub name: String,
    /// Whether it is code, rather than read-only data.
    pub executable: bool,
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
    interpreter_region(version, generate::interpreter(version))
}

/// The JIT output `program` of `executable`: its code, with a symbol per function of the
/// executable, or per BPF instruction with `instruction_symbols`, and its pc section.
///
/// # Panics
///
/// If `program` was not produced by `codegen`.
pub fn jit<C: ContextObject>(
    executable: &Executable<C>,
    program: &JitProgram,
    instruction_symbols: bool,
) -> [Region; 2] {
    assert!(program.dynasm, "not a program of codegen");
    let templates = generate::jit_templates(executable.get_sbpf_version());
    jit_regions(templates, executable, program, instruction_symbols)
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
    std::fs::write(path, elf_image(regions, Layout::Packed))
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

fn supporting_code_region(supports: &SupportingCode) -> Region {
    let (range, symbols) = supporting_code_symbols(supports);
    let bytes = supports.code[..range.len()].to_vec();
    Region {
        name: ".text.supports".to_string(),
        executable: true,
        start: range.start,
        bytes,
        symbols,
    }
}

fn interpreter_region(version: SBPFVersion, interpreter: &Interpreter) -> Region {
    let start = interpreter.steps.as_ptr() as usize;
    Region {
        name: format!(".text.interpreter_{}", version_name(version)),
        executable: true,
        start,
        bytes: interpreter.steps.to_vec(),
        symbols: interpreter_symbols(version, start, &interpreter.step_lens),
    }
}

/// The text section of the sealed `program`, with its symbols, see `jit_symbols`, and its pc
/// section.
fn jit_regions<const SIZE: usize, C: ContextObject>(
    templates: &JitTemplates<SIZE>,
    executable: &Executable<C>,
    program: &JitProgram,
    instruction_symbols: bool,
) -> [Region; 2] {
    let text = program.text_section();
    let pc_section = program.pc_section();
    [
        Region {
            name: ".text.jit".to_string(),
            executable: true,
            start: text.as_ptr() as usize,
            bytes: text.to_vec(),
            symbols: jit_symbols(templates, executable, program, instruction_symbols),
        },
        Region {
            name: ".rodata.jit".to_string(),
            executable: false,
            start: pc_section.as_ptr() as usize,
            bytes: pc_section
                .iter()
                .flat_map(|entry| entry.to_le_bytes())
                .collect(),
            symbols: Vec::new(),
        },
    ]
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

/// Where `elf_image` places the regions in the file.
#[derive(Clone, Copy)]
enum Layout {
    /// One after another, each at the first free page, plus the offset of its address in the page.
    Packed,
    /// As the `len` bytes of the file from `offset` on are mapped at `address`, all of which the
    /// image has, as zeroes where there are no regions. The regions must be among them.
    Mapped {
        address: usize,
        offset: usize,
        len: usize,
    },
}

/// An ELF executable with the `regions`, each of which is a section and a `PT_LOAD` segment at
/// its address, at a file offset congruent to the address modulo the page size so that the file
/// can be mapped at it, as the `layout` says. The symbols of the regions are in `.symtab`.
fn elf_image(regions: &[Region], layout: Layout) -> Vec<u8> {
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
        let reserved = usize::try_from(writer.reserved_len()).unwrap();
        let offset = match layout {
            Layout::Packed => reserved
                .next_multiple_of(PAGE_ALIGNMENT)
                .checked_add(region.start % PAGE_ALIGNMENT)
                .unwrap(),
            Layout::Mapped {
                address,
                offset,
                len,
            } => {
                let in_mapping = region.start.checked_sub(address).unwrap();
                assert!(in_mapping.saturating_add(region.bytes.len()) <= len);
                offset.checked_add(in_mapping).unwrap()
            }
        };
        assert!(
            offset >= reserved,
            "{} overlaps what precedes it",
            region.name
        );
        writer.reserve_until(offset as u64);
        writer.reserve(region.bytes.len() as u64, 1);
        offsets.push(offset);
    }
    // The rest of the mapping, before what follows.
    let mapped_end = match layout {
        Layout::Packed => None,
        Layout::Mapped { offset, len, .. } => Some(offset.checked_add(len).unwrap() as u64),
    };
    if let Some(end) = mapped_end {
        writer.reserve_until(end);
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
            p_flags: if region.executable {
                elf::PF_R | elf::PF_X
            } else {
                elf::PF_R
            },
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
    if let Some(end) = mapped_end {
        writer.pad_until(end);
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
            sh_flags: if region.executable {
                elf::SHF_ALLOC | elf::SHF_EXECINSTR
            } else {
                elf::SHF_ALLOC
            },
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

/// The file offset of the code in the files of `DebugImage`, after the ELF headers: files are
/// mapped from multiples of the page size, and on Windows of the allocation granularity, 64 KiB.
const CODE_OFFSET: usize = 64 * 1024;

/// What the debugging aids make of a piece of generated code: an ELF image of it with its symbols,
/// which is the file that the code is generated into with `Options::code_dir`, and which is
/// registered with the GDB JIT interface with `Options::gdb_jit`.
///
/// Anonymous memory is unnamed to profilers and debuggers. So with a file, `map` maps the pages for
/// the code from it, from `CODE_OFFSET` on, which `/proc/<pid>/maps` names. The mapping is private,
/// so that debuggers can insert breakpoints, and the code reaches the file when `finish` writes the
/// image, with the headers before the mapped part and the symbols after it.
pub(crate) struct DebugImage {
    /// The file and its path.
    file: Option<(File, PathBuf)>,
    /// The address and the length of the mapping of the file, once it is mapped.
    mapped: Option<(usize, usize)>,
}

impl DebugImage {
    /// The image of the code of `label`, see `new_in`.
    pub(in crate::codegen) fn new(label: &str) -> Self {
        Self::new_in(options().code_dir.as_deref(), label)
    }

    /// The image of the next JIT program, labelled `jit-<n>`.
    pub(in crate::codegen) fn new_jit() -> Self {
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        Self::new(&format!("jit-{}", COUNTER.fetch_add(1, Ordering::Relaxed)))
    }

    /// The image of the code of `label`, with the file `sbpf-<pid>-<label>.elf` in `code_dir`.
    ///
    /// # Panics
    ///
    /// If the file cannot be created, as there is no sensible fallback for a debug feature that
    /// is asked for.
    pub(super) fn new_in(code_dir: Option<&Path>, label: &str) -> Self {
        let file = code_dir.map(|directory| {
            let path = directory.join(format!("sbpf-{}-{label}.elf", std::process::id()));
            let mut options = File::options();
            options.read(true).write(true).create(true).truncate(true);
            // To map the file as it is executable, see `MappingBuilder::file`.
            #[cfg(target_os = "windows")]
            std::os::windows::fs::OpenOptionsExt::access_mode(&mut options, {
                use windows_sys::Win32::Foundation::{
                    GENERIC_EXECUTE, GENERIC_READ, GENERIC_WRITE,
                };
                GENERIC_READ | GENERIC_WRITE | GENERIC_EXECUTE
            });
            let file = std::fs::create_dir_all(directory)
                .and_then(|()| options.open(&path))
                .unwrap_or_else(|error| panic!("failed to create {:?}: {}", path, error));
            (file, path)
        });
        Self { file, mapped: None }
    }

    /// Map the pages for the code with `builder`, those of the file if there is one.
    pub(in crate::codegen) fn map(
        &mut self,
        builder: MappingBuilder,
    ) -> Result<Mapping, EbpfError> {
        let Some((file, path)) = &self.file else {
            return builder.build();
        };
        assert!(self.mapped.is_none(), "{:?} is mapped already", path);
        // The pages of the file have to exist.
        let len = round_to_page_size(builder.len(), get_system_page_size());
        file.set_len(CODE_OFFSET.saturating_add(len) as u64)
            .map_err(|error| {
                let errno = error.raw_os_error().unwrap_or(0);
                EbpfError::LibcInvocationFailed("set_len", vec![format!("{path:?}")], errno)
            })?;
        // SAFETY:
        //
        // Contract from `MappingBuilder::file`: Until the mapping is dropped, the file must not be
        // shortened below `offset` plus the length of the mapping, and the bytes there may only be
        // overwritten with those that the mapping has at the same position.
        //
        // Evidence: none for what happens to the file outside of this process, which this cannot
        // prevent, and which is accepted for the debugging aids. `finish` writes what the mapping
        // has, and zeroes where nothing was written to it.
        let mapping = unsafe { builder.file(file, CODE_OFFSET as u64) }.build()?;
        self.mapped = Some((mapping.as_ptr() as usize, len));
        Ok(mapping)
    }

    /// Complete the image, once the code is final, with the `regions` of it, which are in the
    /// mapping of `map` if it mapped the file: write the file, and register the image with the
    /// GDB JIT interface. The registration is returned, which unregisters the image when dropped.
    pub(in crate::codegen) fn finish(
        self,
        regions: impl FnOnce() -> Vec<Region>,
    ) -> Option<Registration> {
        if self.file.is_none() && !options().gdb_jit {
            return None;
        }
        let layout = match self.mapped {
            Some((address, len)) => Layout::Mapped {
                address,
                offset: CODE_OFFSET,
                len,
            },
            None => Layout::Packed,
        };
        let image = elf_image(&regions(), layout);
        if let Some((file, path)) = &self.file {
            write_all_at(file, &image)
                .unwrap_or_else(|error| panic!("failed to write {:?}: {}", path, error));
        }
        options()
            .gdb_jit
            .then(|| Registration::new(image.into_boxed_slice()))
    }
}

/// Write `bytes` to the start of `file`.
fn write_all_at(file: &File, bytes: &[u8]) -> io::Result<()> {
    cfg_select! {
        windows => {
            let (mut bytes, mut offset) = (bytes, 0);
            while !bytes.is_empty() {
                let written = std::os::windows::fs::FileExt::seek_write(file, bytes, offset)?;
                if written == 0 {
                    return Err(io::ErrorKind::WriteZero.into());
                }
                bytes = &bytes[written..];
                offset = offset.saturating_add(written as u64);
            }
            Ok(())
        }
        _ => std::os::unix::fs::FileExt::write_all_at(file, bytes, 0),
    }
}

/// Complete the `image` of the supporting code, which is final, and keep it registered for as long
/// as the process lives, as the code is.
pub(in crate::codegen) fn finish_supporting_code(image: DebugImage, supports: &SupportingCode) {
    std::mem::forget(image.finish(|| vec![supporting_code_region(supports)]));
}

/// Complete the `image` of the interpreter for `version`, whose steps are final, and keep it
/// registered for as long as the process lives, as the interpreter is.
pub(in crate::codegen) fn finish_interpreter(
    image: DebugImage,
    version: SBPFVersion,
    interpreter: &Interpreter,
) {
    std::mem::forget(image.finish(|| vec![interpreter_region(version, interpreter)]));
}

/// Complete the `image` of the sealed `program`, whose registration it keeps.
pub(in crate::codegen) fn finish_jit<const SIZE: usize, C: ContextObject>(
    image: DebugImage,
    templates: &JitTemplates<SIZE>,
    executable: &Executable<C>,
    program: &mut JitProgram,
) {
    let instruction_symbols = options().instruction_symbols;
    program.debug_registration =
        image.finish(|| jit_regions(templates, executable, program, instruction_symbols).into());
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
#[cfg_attr(test, expect(non_upper_case_globals))]
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

/// The registration of an ELF image with the GDB JIT interface: its entry in the list, and the
/// image. It is unregistered when dropped.
pub(crate) struct Registration {
    /// From `Box::into_raw`, and freed after it was removed from the list.
    entry: *mut JitCodeEntry,
    _symfile: Box<[u8]>,
}

// SAFETY:
//
// Contract from `Send`: Types that can be transferred across thread boundaries.
//
// Evidence: `entry` is only accessed by `Registration::new` and `drop`, while holding `LIST_LOCK`,
// so from any thread.
unsafe impl Send for Registration {}
// SAFETY:
//
// Contract from `Sync`: Types for which it is safe to share references between threads.
//
// Contract from `Sync`: The precise definition is: a type `T` is `Sync` if and only if `&T` is
// `Send`. In other words, if there is no possibility of undefined behavior (including data
// races) when passing `&T` references between threads.
//
// Evidence: `&Registration` does not access `entry`.
unsafe impl Sync for Registration {}

impl Registration {
    /// Add the ELF file `symfile` to the list of the debugger.
    fn new(symfile: Box<[u8]>) -> Self {
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
        Self {
            entry,
            _symfile: symfile,
        }
    }
}

impl Drop for Registration {
    /// Remove the entry from the list of the debugger.
    fn drop(&mut self) {
        let entry = self.entry;
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
        // `Registration` is dropped once, so the entry is only freed once. The list no longer has
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
            let flags = if region.executable {
                object::elf::PF_R | object::elf::PF_X
            } else {
                object::elf::PF_R
            };
            assert_eq!(segment.p_flags(endian), flags);
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
            let kind = if region.executable {
                object::SectionKind::Text
            } else {
                object::SectionKind::ReadOnlyData
            };
            assert_eq!(section.kind(), kind);
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
                executable: true,
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
                executable: true,
                start: 0x10_0000,
                bytes: vec![0xcc; 4096],
                symbols: sized_symbols(
                    vec![("a2".to_string(), 0x10_0010), ("a1".to_string(), 0x10_0000)],
                    0x10_1000,
                ),
            },
            Region {
                name: ".text.empty".to_string(),
                executable: true,
                start: 0x30_0000,
                bytes: Vec::new(),
                symbols: Vec::new(),
            },
            Region {
                name: ".rodata.c".to_string(),
                executable: false,
                start: 0x30_1004,
                bytes: vec![1, 2, 3],
                symbols: Vec::new(),
            },
        ];
        check_elf_image(&elf_image(&regions, Layout::Packed), &regions);
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
            let regions = jit(&executable, &program, instruction_symbols);
            let [region, pc_region] = &regions;
            let pc_bytes: Vec<u8> = program
                .pc_section()
                .iter()
                .flat_map(|e| e.to_le_bytes())
                .collect();
            assert_eq!(pc_region.bytes, pc_bytes);
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
            check_elf_image(&elf_image(&regions, Layout::Packed), &regions);
        }
    }

    /// The code is generated into a private mapping of the file, which gets the ELF image once the
    /// code is final, with the regions where they are mapped, and stays as it is when the code is
    /// dropped.
    #[test]
    fn debug_image_file() {
        use crate::memory_management::ReadExecute;
        let directory =
            std::env::temp_dir().join(format!("sbpf-debug-image-{}", std::process::id()));
        let label = "debug-image-test";
        let path = directory.join(format!("sbpf-{}-{label}.elf", std::process::id()));
        let mut image = DebugImage::new_in(Some(&directory), label);
        let page_size = get_system_page_size();
        let mut mapping = image.map(Mapping::builder(2 * page_size).low()).unwrap();
        let start = mapping.as_ptr() as usize;
        assert!(start.saturating_add(2 * page_size) <= 1 << 31);
        let (data, code) = ([1, 2, 3], [0x90, 0xc3]);
        mapping[..data.len()].copy_from_slice(&data);
        mapping[page_size..][..code.len()].copy_from_slice(&code);
        assert!(
            std::fs::read(&path).unwrap().iter().all(|&byte| byte == 0),
            "the writes are private"
        );
        let mapping = mapping.protect::<ReadExecute>().unwrap();
        let regions = [
            Region {
                name: ".rodata.test".to_string(),
                executable: false,
                start,
                bytes: data.to_vec(),
                symbols: Vec::new(),
            },
            Region {
                name: ".text.test".to_string(),
                executable: true,
                start: start + page_size,
                bytes: code.to_vec(),
                symbols: vec![Symbol {
                    name: "f".to_string(),
                    address: start + page_size,
                    size: code.len(),
                }],
            },
        ];
        let registration = image.finish(|| regions.to_vec());
        let file_image = std::fs::read(&path).unwrap();
        assert_eq!(file_image[CODE_OFFSET..][..data.len()], data);
        assert_eq!(file_image[CODE_OFFSET + page_size..][..code.len()], code);
        assert!(file_image.len() >= CODE_OFFSET + 2 * page_size);
        check_elf_image(&file_image, &regions);
        assert_eq!(mapping[page_size..][..code.len()], code);
        drop((registration, mapping));
        assert_eq!(std::fs::read(&path).unwrap(), file_image);
        std::fs::remove_dir_all(&directory).unwrap();
    }
}

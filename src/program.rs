//! Common interface for built-in and user supplied programs
#[cfg(all(feature = "jit", not(target_os = "windows"), target_arch = "x86_64"))]
use crate::{elf::Executable, vm::EbpfVm};
use {
    crate::{
        ebpf,
        elf::ElfError,
        vm::{Config, ContextObject, EncryptedHostAddressToEbpfVm},
    },
    std::collections::{btree_map::Entry, BTreeMap},
};
#[cfg(target_arch = "x86_64")]
use {
    crate::{
        error::EbpfError,
        memory_management::{
            allocate_pages_pooled, free_pages_pooled, get_system_page_size, protect_pages,
            round_to_page_size, PagePermissions,
        },
    },
    std::ptr::NonNull,
};

/// The JIT output for a program, in a single pooled allocation.
pub struct JitProgram {
    /// Size of the pooled allocation: the page-rounded `pc_section`, then the `text_section`.
    allocation_size: usize,
    /// Offset in `text_section` for each BPF instruction.
    ///
    /// Pointers rather than `&'static` slices, so that no borrow can outlive the allocation.
    pc_section: NonNull<[u32]>,
    /// The machine code.
    ///
    /// Before `seal` this is the whole capacity of the code pages.
    text_section: NonNull<[u8]>,
    /// Whether `seal` has made the sections read-only.
    sealed: bool,
    /// Whether the code was produced by `codegen` rather than by the old `jit::JitCompiler`, which
    /// makes the two incompatible in how they are entered.
    pub(crate) dynasm: bool,
}

// SAFETY: `JitProgram` owns its allocation like a `Box<[u8]>` would, and only the compiler writes
// to it, through `&mut self` before `seal`, so before the program is shared.
unsafe impl Send for JitProgram {}
// SAFETY: see `Send`.
unsafe impl Sync for JitProgram {}

impl JitProgram {
    /// Allocate a program with `pc` zeroed entries in the pc section and room for `code_capacity`
    /// bytes of machine code.
    pub(crate) fn new(pc: usize, code_capacity: usize) -> Self {
        let page_size = get_system_page_size();
        let pc_size = round_to_page_size(pc.saturating_mul(std::mem::size_of::<u32>()), page_size);
        let text_capacity = round_to_page_size(code_capacity, page_size);
        // Saturating, so that a nonsensical size fails in the allocator rather than wrapping
        // around to a small allocation.
        let (raw, allocation_size) = allocate_pages_pooled(pc_size.saturating_add(text_capacity));
        let raw = NonNull::new(raw).expect("the pooled allocation is never null");
        // The allocation is page aligned, and the `pc` words fit within `pc_size`, so the
        // sections are aligned and disjoint.
        //
        // SAFETY:
        //
        // Contract from `NonNull::add`: the result must be in bounds of the allocation.
        // Evidence: the allocation has at least `pc_size + text_capacity` bytes, and the result is
        // at `pc_size`.
        let text = unsafe { raw.add(pc_size) };
        let pc_section = NonNull::slice_from_raw_parts(raw.cast::<u32>(), pc);
        // The pc section relies on zero-initialization to distinguish unfilled forward-jump
        // targets from filled backward-jump targets in the old JIT. The pool may hand back
        // recycled memory, so zero just the pc section here.
        //
        // SAFETY:
        //
        // Contract from `ptr::write_bytes`: the range must be valid for writes.
        // Evidence: the `pc` words are within the first `pc_size` bytes of the allocation, which
        // is read-write memory of the pool, and no reference into it exists yet.
        unsafe { std::ptr::write_bytes(pc_section.cast::<u32>().as_ptr(), 0, pc) };
        Self {
            allocation_size,
            pc_section,
            text_section: NonNull::slice_from_raw_parts(text, text_capacity),
            sealed: false,
            dynasm: false,
        }
    }

    /// Offset in `text_section` for each BPF instruction.
    pub fn pc_section(&self) -> &[u32] {
        // SAFETY:
        //
        // Contract from `NonNull::as_ref`: the pointer must be convertible to a reference, and the
        // memory not mutated while the reference lives.
        // Evidence: `pc_section` is within the allocation, which lives as long as `self`, and is
        // only written to through `&mut self`.
        unsafe { self.pc_section.as_ref() }
    }

    /// The machine code, which is executable.
    pub fn text_section(&self) -> &[u8] {
        // SAFETY: as for `pc_section`.
        unsafe { self.text_section.as_ref() }
    }

    /// The pc section to fill in, which is empty once the program is sealed.
    pub(crate) fn pc_section_mut(&mut self) -> &mut [u32] {
        if self.sealed {
            return &mut [];
        }
        // SAFETY:
        //
        // Contract from `NonNull::as_mut`: the pointer must be convertible to a reference, and the
        // memory not accessed through other pointers while the reference lives.
        // Evidence: the section is read-write as `seal` has not protected it, and initialized as
        // `new` zeroed it. References into it only come from borrowing `self`, which is
        // exclusively borrowed here.
        unsafe { self.pc_section.as_mut() }
    }

    /// The machine code to fill in, which is empty once the program is sealed.
    pub(crate) fn text_section_mut(&mut self) -> &mut [u8] {
        if self.sealed {
            return &mut [];
        }
        // SAFETY:
        //
        // Contract from `NonNull::as_mut`: as for `pc_section_mut`.
        // Evidence: the section is read-write as `seal` has not protected it, and initialized as
        // it is mmapped memory of the pool, where a reused block still holds the bytes written
        // before. The exclusive borrow of `self` rules out other references.
        unsafe { self.text_section.as_mut() }
    }

    /// Make the pages read-only and read-execute, with `text_section` shrunk to the `used` length.
    ///
    /// Does nothing if the program is already sealed.
    pub(crate) fn seal(&mut self, used: usize) -> Result<(), EbpfError> {
        if self.sealed {
            return Ok(());
        }
        if used > self.text_section.len() {
            return Err(EbpfError::ExhaustedTextSegment(used));
        }
        let page_size = get_system_page_size();
        let pc_size = round_to_page_size(std::mem::size_of_val(self.pc_section()), page_size);
        let code_size = round_to_page_size(used, page_size);
        let text = self.text_section.as_ptr().cast::<u8>();
        // SAFETY:
        //
        // Contract from `ptr::add`: the result must be in bounds of the allocation.
        // Evidence: `used` is at most the length of `text_section`, checked above.
        let unused = unsafe { text.add(used) };

        // Debugger traps in the unused tail of the last code page.
        //
        // SAFETY:
        //
        // Contract from `ptr::write_bytes`: the range must be valid for writes.
        // Evidence: `code_size` is `used` rounded up to the page size, and the length of
        // `text_section` is page-rounded too, so the range is within it. Its pages are read-write,
        // as nothing has protected them yet, and no reference into them is alive, as references
        // are only created by borrowing `self`.
        unsafe { std::ptr::write_bytes(unused, 0xcc, code_size.wrapping_sub(used)) };

        // SAFETY:
        //
        // Contract from `protect_pages`: the range must be whole pages of a mapping that the
        // caller owns, and nothing may access them in a way the new permissions disallow.
        // Evidence: the pooled allocation is page aligned, starts with `pc_section`, and has the
        // page-rounded `pc_size` bytes for it. `self` owns the allocation, and the section is only
        // read after this.
        unsafe {
            protect_pages(
                self.pc_section.as_ptr().cast::<u8>(),
                pc_size,
                PagePermissions::Read,
            )
        }?;

        // SAFETY: as above, with `text_section` following at the page-rounded `pc_size`, and
        // `code_size` within it. The section is only read and executed after this.
        unsafe { protect_pages(text, code_size, PagePermissions::ReadExecute) }?;
        self.text_section = NonNull::slice_from_raw_parts(self.text_section.cast::<u8>(), used);
        self.sealed = true;
        Ok(())
    }

    /// The length of the host machinecode in bytes
    pub fn machine_code_length(&self) -> usize {
        self.text_section().len()
    }

    /// The total pooled allocation size retained by the compiled program.
    pub fn mem_size(&self) -> usize {
        self.allocation_size
    }

    /// Execute from `vm.registers[11]` with whichever compiler produced this program.
    #[cfg(all(feature = "jit", not(target_os = "windows"), target_arch = "x86_64"))]
    pub(crate) fn run<C: ContextObject>(&self, executable: &Executable<C>, vm: &mut EbpfVm<C>) {
        if self.dynasm {
            self.dynasm_invoke(executable, vm);
        } else {
            let registers = vm.registers;
            self.invoke(executable.get_config(), vm, registers);
        }
    }
}

impl Drop for JitProgram {
    fn drop(&mut self) {
        // SAFETY:
        //
        // Contract from `free_pages_pooled`: the pointer and size must identify a full allocation
        // from `allocate_pages_pooled` that is not freed yet, and no references into it may be
        // retained.
        // Evidence: `pc_section` starts at the allocation and `allocation_size` is what
        // `allocate_pages_pooled` returned with it, both set only by `new`. This is the only
        // place freeing them, and any reference into them borrows `self`.
        unsafe {
            free_pages_pooled(self.pc_section.as_ptr().cast::<u8>(), self.allocation_size);
        }
    }
}

impl std::fmt::Debug for JitProgram {
    fn fmt(&self, fmt: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        fmt.write_fmt(format_args!("JitProgram {:?}", self as *const _))
    }
}

impl PartialEq for JitProgram {
    fn eq(&self, other: &Self) -> bool {
        std::ptr::eq(self, other)
    }
}

/// Defines a set of sbpf_version of an executable
#[derive(Debug, PartialEq, PartialOrd, Eq, Clone, Copy)]
pub enum SBPFVersion {
    /// The legacy format
    V0,
    /// SIMD-0166
    V1,
    /// SIMD-0174, SIMD-0173
    V2,
    /// SIMD-0178, SIMD-0189, SIMD-0377
    V3,
    /// SIMD-0177
    V4,
    /// Used for future versions
    Reserved,
}

impl SBPFVersion {
    /// Enable SIMD-0166: SBPF dynamic stack frames
    ///
    /// Allows usage of `add64 r10, imm`.
    pub fn manual_stack_frame_bump(self) -> bool {
        self == SBPFVersion::V1 || self == SBPFVersion::V2
    }
    /// ... SIMD-0166
    pub fn stack_frame_gaps(self) -> bool {
        self == SBPFVersion::V0
    }

    /// Enable SIMD-0174: SBPF arithmetics improvements
    pub fn enable_pqr(self) -> bool {
        self == SBPFVersion::V2
    }
    /// ... SIMD-0174
    pub fn explicit_sign_extension_of_results(self) -> bool {
        self == SBPFVersion::V2
    }
    /// ... SIMD-0174
    pub fn swap_sub_reg_imm_operands(self) -> bool {
        self == SBPFVersion::V2
    }
    /// ... SIMD-0174
    pub fn disable_neg(self) -> bool {
        self == SBPFVersion::V2
    }

    /// Enable SIMD-0173: SBPF instruction encoding improvements
    pub fn callx_uses_src_reg(self) -> bool {
        self == SBPFVersion::V2
    }
    /// ... SIMD-0173
    pub fn disable_lddw(self) -> bool {
        self == SBPFVersion::V2
    }
    /// ... SIMD-0173
    pub fn disable_le(self) -> bool {
        self == SBPFVersion::V2
    }
    /// ... SIMD-0173
    pub fn move_memory_instruction_classes(self) -> bool {
        self == SBPFVersion::V2
    }

    /// Enable SIMD-0178: SBPF Static Syscalls
    pub fn static_syscalls(self) -> bool {
        self >= SBPFVersion::V3
    }
    /// Enable SIMD-0189: SBPF stricter ELF headers
    pub fn enable_stricter_elf_headers(self) -> bool {
        self >= SBPFVersion::V3
    }
    /// ... SIMD-0189
    pub fn enable_lower_rodata_vaddr(self) -> bool {
        self >= SBPFVersion::V3
    }
    /// ... SIMD-0377
    pub fn enable_jmp32(self) -> bool {
        self >= SBPFVersion::V3
    }
    /// ... SIMD-0377
    pub fn callx_uses_dst_reg(self) -> bool {
        self >= SBPFVersion::V3
    }

    /// Calculate the target program counter for a CALL_IMM instruction depending on
    /// the SBPF version.
    pub fn calculate_call_imm_target_pc(self, pc: usize, imm: i64) -> u32 {
        if self.static_syscalls() {
            (pc as i64).saturating_add(imm).saturating_add(1) as u32
        } else {
            imm as u32
        }
    }
}

/// Holds the function symbols of an Executable
#[derive(Debug, PartialEq, Eq)]
pub struct FunctionRegistry<T> {
    pub(crate) map: BTreeMap<u32, (Vec<u8>, T)>,
}

impl<T> Default for FunctionRegistry<T> {
    fn default() -> Self {
        Self {
            map: BTreeMap::new(),
        }
    }
}

impl<T: Copy + PartialEq> FunctionRegistry<T> {
    /// Register a symbol with an explicit key
    pub fn register_function(
        &mut self,
        key: u32,
        name: impl Into<Vec<u8>>,
        value: T,
    ) -> Result<(), ElfError> {
        match self.map.entry(key) {
            Entry::Vacant(entry) => {
                entry.insert((name.into(), value));
            }
            Entry::Occupied(entry) => {
                if entry.get().1 != value {
                    return Err(ElfError::SymbolHashCollision(key));
                }
            }
        }
        Ok(())
    }

    /// Used for transitioning from SBPFv0 to SBPFv3
    pub(crate) fn register_function_hashed_legacy<C: ContextObject>(
        &mut self,
        loader: &BuiltinProgram<C>,
        hash_symbol_name: bool,
        name: impl Into<Vec<u8>>,
        value: T,
    ) -> Result<u32, ElfError>
    where
        usize: From<T>,
    {
        let name = name.into();
        let config = loader.get_config();
        let key = if hash_symbol_name {
            let hash = if name == b"entrypoint" {
                ebpf::hash_symbol_name(b"entrypoint")
            } else {
                ebpf::hash_symbol_name(&usize::from(value).to_le_bytes())
            };
            if loader.get_function_registry().lookup_by_key(hash).is_some() {
                return Err(ElfError::SymbolHashCollision(hash));
            }
            hash
        } else {
            usize::from(value) as u32
        };
        self.register_function(
            key,
            if config.enable_symbol_and_section_labels || name == b"entrypoint" {
                name
            } else {
                Vec::default()
            },
            value,
        )?;
        Ok(key)
    }

    /// Unregister a symbol again
    pub fn unregister_function(&mut self, key: u32) -> bool {
        self.map.remove(&key).is_some()
    }

    /// Iterate over all keys
    pub fn keys(&self) -> impl Iterator<Item = u32> + '_ {
        self.map.keys().copied()
    }

    /// Iterate over all entries
    pub fn iter(&self) -> impl Iterator<Item = (u32, (&[u8], T))> + '_ {
        self.map
            .iter()
            .map(|(key, (name, value))| (*key, (name.as_slice(), *value)))
    }

    /// Get a function by its key
    pub fn lookup_by_key(&self, key: u32) -> Option<(&[u8], T)> {
        // String::from_utf8_lossy(function_name).as_str()
        self.map
            .get(&key)
            .map(|(function_name, value)| (function_name.as_slice(), *value))
    }

    /// Get a function by its name
    pub fn lookup_by_name(&self, name: &[u8]) -> Option<(&[u8], T)> {
        self.map
            .values()
            .find(|(function_name, _value)| function_name == name)
            .map(|(function_name, value)| (function_name.as_slice(), *value))
    }

    /// Calculate memory size
    pub fn mem_size(&self) -> usize {
        std::mem::size_of::<Self>().saturating_add(self.map.iter().fold(
            0,
            |state: usize, (_, (name, value))| {
                state.saturating_add(
                    std::mem::size_of_val(value).saturating_add(
                        std::mem::size_of_val(name).saturating_add(name.capacity()),
                    ),
                )
            },
        ))
    }
}

/// Syscall handler function (ContextObject is derived from VM)
pub type BuiltinFunction<C> = fn(EncryptedHostAddressToEbpfVm<C>, u64, u64, u64, u64, u64);
/// Re-export of the JIT compiler for the declare_builtin_function! macro
#[cfg(all(feature = "jit", not(target_os = "windows"), target_arch = "x86_64"))]
pub type JitCompiler<'a, C> = crate::jit::JitCompiler<'a, C>;
/// Re-export of the JIT compiler for the declare_builtin_function! macro
#[cfg(not(all(feature = "jit", not(target_os = "windows"), target_arch = "x86_64")))]
pub struct JitCompiler<'a, C> {
    _phantom: std::marker::PhantomData<&'a C>,
}
#[cfg(not(all(feature = "jit", not(target_os = "windows"), target_arch = "x86_64")))]
impl<'a, C: ContextObject> JitCompiler<'a, C> {
    /// Dummy for declare_builtin_function!()
    #[allow(dead_code)]
    pub fn emit_external_call(&mut self, _function: BuiltinFunction<C>) {}
}
/// Syscall codegen function for JIT compiler
pub type BuiltinCodegen<C> = fn(&mut JitCompiler<C>);

/// Represents the interface to a fixed functionality program
#[derive(Eq)]
pub struct BuiltinProgram<C: ContextObject> {
    /// Holds the Config if this is a loader program
    config: Option<Box<Config>>,
    /// Function pointers by symbol with sparse indexing
    sparse_registry: FunctionRegistry<(BuiltinFunction<C>, BuiltinCodegen<C>)>,
}

impl<C: ContextObject> PartialEq for BuiltinProgram<C> {
    fn eq(&self, other: &Self) -> bool {
        self.config.eq(&other.config) && self.sparse_registry.eq(&other.sparse_registry)
    }
}

impl<C: ContextObject> BuiltinProgram<C> {
    /// Constructs a loader built-in program
    pub fn new_loader(config: Config) -> Self {
        Self {
            config: Some(Box::new(config)),
            sparse_registry: FunctionRegistry::default(),
        }
    }

    /// Constructs a built-in program
    pub fn new_builtin() -> Self {
        Self {
            config: None,
            sparse_registry: FunctionRegistry::default(),
        }
    }

    /// Constructs a mock loader built-in program
    pub fn new_mock() -> Self {
        Self {
            config: Some(Box::default()),
            sparse_registry: FunctionRegistry::default(),
        }
    }

    /// Get the configuration settings assuming this is a loader program
    pub fn get_config(&self) -> &Config {
        self.config.as_ref().unwrap()
    }

    /// Get the function registry depending on the SBPF version
    pub fn get_function_registry(
        &self,
    ) -> &FunctionRegistry<(BuiltinFunction<C>, BuiltinCodegen<C>)> {
        &self.sparse_registry
    }

    /// Calculate memory size
    pub fn mem_size(&self) -> usize {
        std::mem::size_of::<Self>()
            .saturating_add(if self.config.is_some() {
                std::mem::size_of::<Config>()
            } else {
                0
            })
            .saturating_add(self.sparse_registry.mem_size())
    }

    /// Register a function both in the sparse and dense registries
    ///
    /// This is a low-level function. Prefer using [`Self::register_definition`].
    pub fn register_function(
        &mut self,
        name: &str,
        entry: (BuiltinFunction<C>, BuiltinCodegen<C>),
    ) -> Result<(), ElfError> {
        let key = ebpf::hash_symbol_name(name.as_bytes());
        self.sparse_registry
            .register_function(key, name, entry)
            .map(|_| ())
    }

    /// Register a function both in the sparse and dense registries
    pub fn register_definition<BFD: BuiltinFunctionDefinition<C>>(
        &mut self,
        name: &str,
    ) -> Result<(), ElfError> {
        self.register_function(name, (BFD::vm, BFD::codegen))
    }

    /// Remove a function by name (if it exists)
    pub fn unregister_function(&mut self, name: &str) -> bool {
        let key = ebpf::hash_symbol_name(name.as_bytes());
        self.sparse_registry.unregister_function(key)
    }
}

/// Native built-in functions that can be made available to programs to call.
pub trait BuiltinFunctionDefinition<C>
where
    C: crate::vm::ContextObject,
{
    /// Error type returned by this built-in function.
    type Error: Into<Box<dyn core::error::Error>>;

    /// The Rust side of the function logic.
    ///
    /// This is the only method you are required to override.
    fn rust(
        vm: &mut C,
        arg_a: u64,
        arg_b: u64,
        arg_c: u64,
        arg_d: u64,
        arg_e: u64,
    ) -> Result<u64, Self::Error>;

    /// The VM wrapper.
    #[expect(clippy::arithmetic_side_effects)]
    fn vm(mut vm: EncryptedHostAddressToEbpfVm<C>, a: u64, b: u64, c: u64, d: u64, e: u64) {
        unsafe {
            // SAFETY: Sound under the stacked lifetimes model – we've only one `VmAddress`.
            vm.with_vm(|vm| {
                let enable_insn_meter = vm.loader.get_config().enable_instruction_meter;
                if enable_insn_meter {
                    let used_cus = vm.previous_instruction_meter - vm.due_insn_count;
                    vm.context().consume(used_cus);
                }
                let converted_result: crate::error::ProgramResult =
                    Self::rust(vm.context(), a, b, c, d, e)
                        .map_err(|err| crate::error::EbpfError::SyscallError(err.into()))
                        .into();
                vm.program_result = converted_result;
                if enable_insn_meter {
                    vm.previous_instruction_meter = vm.context().get_remaining();
                }
            })
        }
    }

    /// Hook for the JIT compiler on how to codegen this built-in function.
    ///
    /// You could opt to codegen it in-line, but do note that defining the other methods is still
    /// required for non-JIT execution modes.
    fn codegen(jit: &mut JitCompiler<C>) {
        jit.emit_external_call(Self::vm);
    }

    /// Register this syscall to the provided program.
    fn register(program: &mut BuiltinProgram<C>, name: &str) -> Result<(), ElfError>
    where
        Self: Sized,
    {
        program.register_definition::<Self>(name)
    }
}

impl<C: ContextObject> std::fmt::Debug for BuiltinProgram<C> {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> Result<(), std::fmt::Error> {
        f.debug_struct("BuiltinProgram")
            .field("registry", unsafe {
                std::mem::transmute::<
                    &FunctionRegistry<(BuiltinFunction<C>, BuiltinCodegen<C>)>,
                    &FunctionRegistry<(usize, usize)>,
                >(&self.sparse_registry)
            })
            .finish()
    }
}

/// Generates an adapter for a BuiltinFunction between the Rust and the VM interface
#[macro_export]
macro_rules! declare_builtin_function {
    (
        $(#[$attr:meta])*
        $name:ident $(<$($generic_ident:tt : $generic_type:tt),+>)?,
        fn rust(
            $vm:ident : &mut $ContextObject:ty,
            $arg_a:ident : u64,
            $arg_b:ident : u64,
            $arg_c:ident : u64,
            $arg_d:ident : u64,
            $arg_e:ident : u64,
        ) -> Result<$Ok:ty, $Err:ty> {
            $($rust:tt)*
        }
        $(fn codegen($jit:ident : &mut JitCompiler<$ContextObject2:ty>) {
            $($codegen:tt)*
        })?
    ) => {
        $(#[$attr])*
        pub struct $name $(<$($generic_ident),+>)? (
            $(std::marker::PhantomData<($($generic_ident,)+)>)?
        );
        impl $(<$($generic_ident : $generic_type),+>)?
            $crate::program::BuiltinFunctionDefinition<$ContextObject> for
            $name $(<$($generic_ident),+>)?
        {
            type Error = $Err;
            fn rust(
                $vm: &mut $ContextObject,
                $arg_a: u64,
                $arg_b: u64,
                $arg_c: u64,
                $arg_d: u64,
                $arg_e: u64,
            ) -> core::result::Result<$Ok, $Err> {
                $($rust)*
            }
            $(fn codegen(
                $jit: &mut $crate::program::JitCompiler<$ContextObject2>,
            ) {
                $($codegen)*
            })?
        }
    };
}

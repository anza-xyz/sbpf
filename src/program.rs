//! Common interface for built-in and user supplied programs
use {
    crate::{
        ebpf,
        elf::ElfError,
        error::EbpfError,
        memory_management::{
            allocate_pages_pooled, free_pages_pooled, get_system_page_size, protect_pages,
            round_to_page_size, PagePermissions,
        },
        vm::{Config, ContextObject, EncryptedHostAddressToEbpfVm},
    },
    std::collections::{btree_map::Entry, BTreeMap},
    std::fmt,
    std::ptr::NonNull,
};

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
            if loader.syscall_registry().lookup_by_key(hash).is_some() {
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

/// A map of syscall functions.
///
/// This map uses a different implementation compared to [`FunctionRegistry`] – it implements fast
/// lookups, but is poor at handling arbitrary insertions quickly. Making this type suitable for
/// small sets of trusted keys only, such as syscalls.
pub struct SyscallRegistry<T> {
    /// The odd multiplier the keys are mixed with, see `index`.
    seed: u32,
    /// The slot of each syscall is the one that its key says, see `index`, which no other key is in.
    /// The other slots are unpopulated, holding a key whose slot is another one, which thus never
    /// matches a key that is looked up there.
    slots: Box<[SyscallSlot<T>]>,
    /// The names of the syscalls in `slots`, at the same indices.
    names: Box<[Box<[u8]>]>,
    /// The number of syscalls.
    len: usize,
}

#[derive(Clone, Copy)]
struct SyscallSlot<T> {
    key: u32,
    value: T,
}

impl<T> Default for SyscallRegistry<T> {
    fn default() -> Self {
        Self {
            seed: SyscallRegistry::<T>::SEED,
            slots: Box::new([]),
            names: Box::new([]),
            len: 0,
        }
    }
}

impl<T: Copy + PartialEq> PartialEq for SyscallRegistry<T> {
    fn eq(&self, other: &Self) -> bool {
        self.len == other.len
            && self
                .iter()
                .all(|(key, syscall)| other.lookup_by_key(key) == Some(syscall))
    }
}

impl<T: Copy + Eq> Eq for SyscallRegistry<T> {}

impl<T: Copy + PartialEq + fmt::Debug> fmt::Debug for SyscallRegistry<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let map = fmt::from_fn(|f| f.debug_map().entries(self.iter()).finish());
        f.debug_struct("SyscallRegistry")
            .field("map", &map)
            .finish()
    }
}

impl<T> SyscallRegistry<T> {
    /// 2^32 divided by the golden ratio, as in Fibonacci hashing. The seeds that are tried are its
    /// odd multiples, which are spread evenly over the 32-bit numbers, starting with itself.
    const SEED: u32 = 0x9e37_79b9;
    /// How many seeds to try at each length.
    const SEEDS: u32 = 32;
    /// The fewest unpopulated slots of a new layout.
    const MIN_UNPOPULATED: usize = 5;
}

impl<T: Copy + PartialEq> SyscallRegistry<T> {
    /// Register a syscall with an explicit key
    pub fn register_function(
        &mut self,
        key: u32,
        name: impl Into<Vec<u8>>,
        value: T,
    ) -> Result<(), ElfError> {
        if let Some((_, slot)) = self.slot(key) {
            return if slot.value == value {
                Ok(())
            } else {
                Err(ElfError::SymbolHashCollision(key))
            };
        }
        let syscall = SyscallSlot { key, value };
        let name = name.into().into_boxed_slice();
        let (seed, len) = (self.seed, self.slots.len());
        let index = Self::index(key, seed, len);
        match self.slots.get(index) {
            Some(slot) if Self::index(slot.key, seed, len) != index => {
                self.slots[index] = syscall;
                self.names[index] = name;
                self.len = self.len.saturating_add(1);
            }
            _ => self.lay_out(syscall, name),
        }
        Ok(())
    }

    /// Unregister a syscall again
    pub fn unregister_function(&mut self, key: u32) -> bool {
        let Some((index, _)) = self.slot(key) else {
            return false;
        };
        self.slots[index].key = Self::unpopulated_key(index, self.seed, self.slots.len());
        self.names[index] = Box::default();
        self.len = self.len.saturating_sub(1);
        true
    }

    /// Iterate over all keys
    pub fn keys(&self) -> impl Iterator<Item = u32> + '_ {
        Self::populated(&self.slots, self.seed).map(|(_, slot)| slot.key)
    }

    /// Iterate over all entries
    pub fn iter(&self) -> impl Iterator<Item = (u32, (&[u8], T))> + '_ {
        Self::populated(&self.slots, self.seed)
            .map(move |(index, slot)| (slot.key, (self.name(index), slot.value)))
    }

    /// Get a syscall by its key
    #[inline]
    pub fn lookup_by_key(&self, key: u32) -> Option<(&[u8], T)> {
        self.slot(key)
            .map(|(index, slot)| (self.name(index), slot.value))
    }

    /// Get a syscall by its name
    pub fn lookup_by_name(&self, name: &[u8]) -> Option<(&[u8], T)> {
        self.iter()
            .map(|(_key, syscall)| syscall)
            .find(|(syscall_name, _value)| *syscall_name == name)
    }

    /// Calculate memory size
    pub fn mem_size(&self) -> usize {
        std::mem::size_of::<Self>()
            .saturating_add(std::mem::size_of_val(&*self.slots))
            .saturating_add(
                self.names
                    .iter()
                    .fold(std::mem::size_of_val(&*self.names), |size, name| {
                        size.saturating_add(name.len())
                    }),
            )
    }

    /// The slot of `key` with `seed` in a vector of `len` slots.
    #[inline]
    fn index(key: u32, seed: u32, len: usize) -> usize {
        (u64::from(key.wrapping_mul(seed)).wrapping_mul(len as u64) >> 32) as usize
    }

    /// A key whose slot is not the one at `index`, which marks that as unpopulated: 0, whose slot is
    /// the first one, or else the first key whose slot is not.
    fn unpopulated_key(index: usize, seed: u32, len: usize) -> u32 {
        if index != 0 {
            return 0;
        }
        (1..=u32::MAX)
            .find(|&key| Self::index(key, seed, len) != 0)
            .expect("the keys map to every one of several slots")
    }

    /// The index and the slot of the syscall of `key`, if there is one.
    #[inline]
    fn slot(&self, key: u32) -> Option<(usize, &SyscallSlot<T>)> {
        let index = Self::index(key, self.seed, self.slots.len());
        let slot = self.slots.get(index)?;
        (slot.key == key).then_some((index, slot))
    }

    /// The name of the syscall in the slot at `index`.
    #[inline]
    fn name(&self, index: usize) -> &[u8] {
        self.names.get(index).map_or(&[], |name| name)
    }

    /// The indices of the populated ones of `slots` with `seed`, and their syscalls.
    fn populated(
        slots: &[SyscallSlot<T>],
        seed: u32,
    ) -> impl Iterator<Item = (usize, &SyscallSlot<T>)> + '_ {
        slots
            .iter()
            .enumerate()
            .filter(move |(index, slot)| Self::index(slot.key, seed, slots.len()) == *index)
    }

    /// Lay the syscalls out again with the new `syscall` and its `name`: at the first length and
    /// seed tried at which no two keys share a slot, from the current length on, with at least
    /// `MIN_UNPOPULATED` slots to spare, or a tenth of them. Such lengths are longer, the more
    /// syscalls there are, so the length grows by an eighth after each that does not do.
    fn lay_out(&mut self, syscall: SyscallSlot<T>, name: Box<[u8]>) {
        let count = self.len.saturating_add(1);
        let mut len = self
            .slots
            .len()
            .max(count.saturating_add(Self::MIN_UNPOPULATED))
            .max(count.saturating_add(count / 9));
        loop {
            for i in 0..Self::SEEDS {
                let seed = Self::SEED.wrapping_mul(i.wrapping_mul(2) | 1);
                let Some(slots) = self.lay_out_with(syscall, seed, len) else {
                    continue;
                };
                let mut names: Box<[Box<[u8]>]> = (0..len).map(|_| Box::default()).collect();
                for (index, slot) in Self::populated(&self.slots, self.seed) {
                    names[Self::index(slot.key, seed, len)] =
                        std::mem::take(&mut self.names[index]);
                }
                names[Self::index(syscall.key, seed, len)] = name;
                *self = Self {
                    seed,
                    slots,
                    names,
                    len: count,
                };
                return;
            }
            len = len.saturating_add((len / 8).max(1));
        }
    }

    /// The slots of the syscalls and the new `syscall` with `seed` and `len`, unless two share one.
    fn lay_out_with(
        &self,
        syscall: SyscallSlot<T>,
        seed: u32,
        len: usize,
    ) -> Option<Box<[SyscallSlot<T>]>> {
        let mut slots: Box<[_]> = (0..len)
            .map(|index| SyscallSlot {
                key: Self::unpopulated_key(index, seed, len),
                value: syscall.value,
            })
            .collect();
        let syscalls = Self::populated(&self.slots, self.seed).map(|(_, slot)| *slot);
        for syscall in syscalls.chain(std::iter::once(syscall)) {
            let index = Self::index(syscall.key, seed, len);
            // Collision: slot already occupied.
            if Self::index(slots[index].key, seed, len) == index {
                return None;
            }
            slots[index] = syscall;
        }
        Some(slots)
    }
}

/// The JIT output for a program, in a single pooled allocation.
pub struct JitProgram {
    /// Size of the pooled allocation.
    allocation_size: usize,
    /// Offset to each BPF instruction's machine code within `text_section`.
    pc_section: NonNull<[u32]>,
    /// The executable machine code.
    text_section: NonNull<[u8]>,
    /// Whether [`Self::seal`] has been invoked.
    sealed: bool,
}

unsafe impl Send for JitProgram {}
unsafe impl Sync for JitProgram {}

impl JitProgram {
    /// Allocate a program with `pc` zeroed entries in the pc section and room for `code_capacity`
    /// bytes of machine code.
    pub fn new(pc: usize, code_capacity: usize) -> Self {
        let page_size = get_system_page_size();
        let pc_size = round_to_page_size(pc.saturating_mul(std::mem::size_of::<u32>()), page_size);
        let text_capacity = round_to_page_size(code_capacity, page_size);
        let (raw, allocation_size) = allocate_pages_pooled(pc_size.saturating_add(text_capacity));
        let raw = NonNull::new(raw).expect("the pooled allocation is never null");
        let text = unsafe { raw.add(pc_size) };
        let pc_section = NonNull::slice_from_raw_parts(raw.cast::<u32>(), pc);
        // The pc section relies on zero-initialization to distinguish unfilled forward-jump
        // targets from filled backward-jump targets in the old JIT. The pool may hand back
        // recycled memory. Zero just the pc section here.
        unsafe { std::ptr::write_bytes(pc_section.cast::<u32>().as_ptr(), 0, pc) };
        Self {
            allocation_size,
            pc_section,
            text_section: NonNull::slice_from_raw_parts(text, text_capacity),
            sealed: false,
        }
    }

    /// Offset in `text_section` for each BPF instruction.
    pub fn pc_section(&self) -> &[u32] {
        unsafe { self.pc_section.as_ref() }
    }

    /// The machine code, which is executable.
    pub fn text_section(&self) -> &[u8] {
        unsafe { self.text_section.as_ref() }
    }

    /// The pc section to fill in, which is empty once the program is sealed.
    pub fn pc_section_mut(&mut self) -> &mut [u32] {
        if self.sealed {
            return &mut [];
        }
        unsafe { self.pc_section.as_mut() }
    }

    /// The machine code to fill in, which is empty once the program is sealed.
    pub fn text_section_mut(&mut self) -> &mut [u8] {
        if self.sealed {
            return &mut [];
        }
        unsafe { self.text_section.as_mut() }
    }

    /// Make the pages read-only and read-execute, with `text_section` shrunk to the `used` length.
    ///
    /// Does nothing if the program is already sealed.
    pub fn seal(&mut self, used: usize) -> Result<(), EbpfError> {
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
        let unused = unsafe { text.add(used) };

        // x64 debugger traps in the unused tail of the last code page.
        // FIXME: this should be architecture-independent somehow.
        unsafe { std::ptr::write_bytes(unused, 0xcc, code_size.wrapping_sub(used)) };

        unsafe {
            self.sealed = true;
            protect_pages(
                self.pc_section.as_ptr().cast::<u8>(),
                pc_size,
                PagePermissions::Read,
            )?;
            protect_pages(text, code_size, PagePermissions::ReadExecute)?;
        };
        self.text_section = NonNull::slice_from_raw_parts(self.text_section.cast::<u8>(), used);
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
}

impl Drop for JitProgram {
    fn drop(&mut self) {
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
    /// The syscalls by the hashes of their names
    syscall_registry: SyscallRegistry<(BuiltinFunction<C>, BuiltinCodegen<C>)>,
}

impl<C: ContextObject> PartialEq for BuiltinProgram<C> {
    fn eq(&self, other: &Self) -> bool {
        self.config.eq(&other.config) && self.syscall_registry.eq(&other.syscall_registry)
    }
}

impl<C: ContextObject> BuiltinProgram<C> {
    /// Constructs a loader built-in program
    pub fn new_loader(config: Config) -> Self {
        Self {
            config: Some(Box::new(config)),
            syscall_registry: SyscallRegistry::default(),
        }
    }

    /// Constructs a built-in program
    pub fn new_builtin() -> Self {
        Self {
            config: None,
            syscall_registry: SyscallRegistry::default(),
        }
    }

    /// Constructs a mock loader built-in program
    pub fn new_mock() -> Self {
        Self {
            config: Some(Box::default()),
            syscall_registry: SyscallRegistry::default(),
        }
    }

    /// Get the configuration settings assuming this is a loader program
    pub fn get_config(&self) -> &Config {
        self.config.as_ref().unwrap()
    }

    /// Get the registry of the syscalls
    pub fn syscall_registry(&self) -> &SyscallRegistry<(BuiltinFunction<C>, BuiltinCodegen<C>)> {
        &self.syscall_registry
    }

    /// Calculate memory size
    pub fn mem_size(&self) -> usize {
        std::mem::size_of::<Self>()
            .saturating_add(if self.config.is_some() {
                std::mem::size_of::<Config>()
            } else {
                0
            })
            .saturating_add(self.syscall_registry.mem_size())
    }

    /// Register a syscall
    ///
    /// This is a low-level function. Prefer using [`Self::register_definition`].
    pub fn register_function(
        &mut self,
        name: &str,
        entry: (BuiltinFunction<C>, BuiltinCodegen<C>),
    ) -> Result<(), ElfError> {
        let key = ebpf::hash_symbol_name(name.as_bytes());
        self.syscall_registry
            .register_function(key, name, entry)
            .map(|_| ())
    }

    /// Register a syscall
    pub fn register_definition<BFD: BuiltinFunctionDefinition<C>>(
        &mut self,
        name: &str,
    ) -> Result<(), ElfError> {
        self.register_function(name, (BFD::vm, BFD::codegen))
    }

    /// Remove a function by name (if it exists)
    pub fn unregister_function(&mut self, name: &str) -> bool {
        let key = ebpf::hash_symbol_name(name.as_bytes());
        self.syscall_registry.unregister_function(key)
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
            .field("registry", &self.syscall_registry)
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

#[cfg(test)]
mod tests {
    use super::*;

    macro_rules! check_lookups {
        ($registry:ident, $lens:expr) => {
            let key = |i: u32| ebpf::hash_symbol_name(&i.to_le_bytes());
            for len in $lens {
                let mut registry = $registry::default();
                for i in 0..len {
                    registry
                        .register_function(key(i), format!("f{i}"), i)
                        .unwrap();
                }
                let found = |registry: &$registry<u32>, i: u32| {
                    registry
                        .lookup_by_key(key(i))
                        .map(|(name, value)| (String::from_utf8(name.to_vec()).unwrap(), value))
                };
                for i in 0..len {
                    assert_eq!(found(&registry, i), Some((format!("f{i}"), i)));
                }
                for i in len..len.saturating_add(1000) {
                    assert_eq!(found(&registry, i), None);
                }
                let mut keys: Vec<_> = (0..len).map(key).collect();
                keys.sort();
                let mut registered: Vec<_> = registry.keys().collect();
                registered.sort();
                assert_eq!(registered, keys);
                let mut iterated: Vec<_> = registry.iter().map(|(key, _)| key).collect();
                iterated.sort();
                assert_eq!(iterated, keys);
                if len > 0 {
                    assert!(registry.register_function(key(0), "f0", 0).is_ok());
                    assert!(matches!(
                        registry.register_function(key(0), "f0", 1),
                        Err(ElfError::SymbolHashCollision(_))
                    ));
                    assert!(registry.unregister_function(key(0)));
                    assert!(!registry.unregister_function(key(0)));
                    assert_eq!(found(&registry, 0), None);
                    for i in 1..len {
                        assert_eq!(found(&registry, i), Some((format!("f{i}"), i)));
                    }
                    assert_eq!(registry.keys().count(), (len as usize).saturating_sub(1));
                    registry.register_function(key(0), "f0", 0).unwrap();
                    assert_eq!(found(&registry, 0), Some(("f0".to_string(), 0)));
                    for i in 0..len {
                        assert!(registry.unregister_function(key(i)));
                    }
                    assert_eq!(registry.keys().count(), 0);
                    for i in 0..len.saturating_add(1000) {
                        assert_eq!(found(&registry, i), None);
                    }
                }
            }
        };
    }

    #[test]
    fn function_registry_lookups() {
        check_lookups!(FunctionRegistry, [0u32, 1, 3, 64, 1000]);
    }

    #[test]
    fn syscall_registry_lookups() {
        check_lookups!(SyscallRegistry, [0u32, 1, 3, 64, 128]);
    }
}

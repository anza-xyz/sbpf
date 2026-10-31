//! This module defines memory regions

use crate::{
    aligned_memory::Pod,
    ebpf,
    error::{EbpfError, ProgramResult, StableResult},
    program::SBPFVersion,
    vm::Config,
};
use std::fmt::Formatter;
use std::{array, cell::UnsafeCell, fmt, mem, ops::Range, ptr};

/* Explanation of the Gapped Memory

    The MemoryMapping supports a special mapping mode which is used for the stack MemoryRegion.
    In this mode the backing address space of the host is sliced in power-of-two aligned frames.
    The exponent of this alignment is specified in vm_gap_shift. Then the virtual address space
    of the guest is spread out in a way which leaves gaps, the same size as the frames, in
    between the frames. This effectively doubles the size of the guests virtual address space.
    But the actual mapped memory stays the same, as the gaps are not mapped and accessing them
    results in an AccessViolation.

    Guest: frame 0 | gap 0 | frame 1 | gap 1 | frame 2 | gap 2 | ...
              |                /                 /
              |          *----*    *------------*
              |         /         /
    Host:  frame 0 | frame 1 | frame 2 | ...
*/

/// Callback executed before generate_access_violation()
pub type AccessViolationHandler = Box<dyn Fn(&mut MemoryRegion, u64, AccessType, u64, u64)>;
/// Fail always
#[allow(clippy::result_unit_err)]
pub fn default_access_violation_handler(
    _region: &mut MemoryRegion,
    _region_max_len: u64,
    _access_type: AccessType,
    _vm_addr: u64,
    _len: u64,
) {
}

/// Types that can be used as backing memory for memory mappings.
///
/// ## Safety
///
/// The implementers must ensure that the returned address and byte length are contained by the
/// implementing type's objects.
pub unsafe trait HostMemoryObject {
    /// The provenance-exposed address in the host address space for this object.
    ///
    /// Normally this is just an address of the pointer.
    fn host(self) -> HostBuffer;
}

/// Types that can be directly mapped into VM memory space should implement this trait.
///
/// The blanket implementations of [`HostMemoryObject`] for `*const T` where `T: VmExposable` allow
/// exposing the implementing types to the guests directly.
pub trait VmExposable {}

/// Types that can be directly and mutably mapped into VM memory space.
///
/// The blanket implementations of [`HostMemoryObject`] for `*mut T` where `T: VmExposableMut` allow
/// mutably exposing the implementing types to the guests directly.
///
/// ## Safety
///
/// The type must not have any invariants that could be broken by the guest's modifications to the
/// data within objects of this type.
pub unsafe trait VmExposableMut {}

unsafe impl VmExposableMut for u8 {}
impl<T: VmExposableMut> VmExposable for T {}

unsafe impl<T: VmExposable> HostMemoryObject for *const T {
    fn host(self) -> HostBuffer {
        HostBuffer::Immutable(ptr::slice_from_raw_parts(
            self.cast(),
            std::mem::size_of::<T>(),
        ))
    }
}

unsafe impl<T: VmExposableMut> HostMemoryObject for *mut T {
    fn host(self) -> HostBuffer {
        HostBuffer::Mutable(ptr::slice_from_raw_parts_mut(
            self.cast(),
            std::mem::size_of::<T>(),
        ))
    }
}

unsafe impl<T: VmExposable> HostMemoryObject for *const [T] {
    fn host(self) -> HostBuffer {
        HostBuffer::Immutable(ptr::slice_from_raw_parts(
            self.cast(),
            self.len().checked_mul(core::mem::size_of::<T>()).unwrap(),
        ))
    }
}

unsafe impl<T: VmExposableMut> HostMemoryObject for *mut [T] {
    fn host(self) -> HostBuffer {
        HostBuffer::Mutable(ptr::slice_from_raw_parts_mut(
            self.cast(),
            self.len().checked_mul(core::mem::size_of::<T>()).unwrap(),
        ))
    }
}

unsafe impl<T: VmExposable, const N: usize> HostMemoryObject for *const [T; N] {
    fn host(self) -> HostBuffer {
        HostBuffer::Immutable(ptr::slice_from_raw_parts(
            self.cast(),
            N.checked_mul(core::mem::size_of::<T>()).unwrap(),
        ))
    }
}

unsafe impl<T: VmExposableMut, const N: usize> HostMemoryObject for *mut [T; N] {
    fn host(self) -> HostBuffer {
        HostBuffer::Mutable(ptr::slice_from_raw_parts_mut(
            self.cast(),
            N.checked_mul(core::mem::size_of::<T>()).unwrap(),
        ))
    }
}

/// Either mutable or immutable slice, returned by [`MemoryRegion::host_buffer`].
#[derive(PartialEq, Eq, Copy, Clone, Debug)]
pub enum HostBuffer {
    /// The `MemoryRegion` is read-only.
    Immutable(*const [u8]),
    /// The `MemoryRegion` is writable (`AccessType::Store` is permitted.)
    Mutable(*mut [u8]),
}

impl HostBuffer {
    /// The length of this host buffer.
    pub fn len(&self) -> usize {
        match self {
            HostBuffer::Immutable(p) => p.len(),
            HostBuffer::Mutable(p) => p.len(),
        }
    }

    /// `true` if this host buffer has a length of 0.
    pub fn is_empty(&self) -> bool {
        match self {
            HostBuffer::Immutable(p) => p.is_empty(),
            HostBuffer::Mutable(p) => p.is_empty(),
        }
    }

    /// `true` if this is a `HostBuffer::Mutable`.
    pub fn is_mutable(&self) -> bool {
        matches!(self, HostBuffer::Mutable(_))
    }

    /// Make this host buffer mutable.
    ///
    /// # Safety
    ///
    /// This host buffer *must* have been initially constructed with a mutable pointer.
    pub unsafe fn mutable(self) -> Self {
        match self {
            HostBuffer::Immutable(p) => HostBuffer::Mutable(p.cast_mut()),
            HostBuffer::Mutable(_) => self,
        }
    }

    /// Make this host buffer immutable.
    pub fn immutable(self) -> Self {
        match self {
            HostBuffer::Immutable(_) => self,
            HostBuffer::Mutable(p) => Self::Immutable(p.cast_const()),
        }
    }

    /// Subslice this host buffer with the provided range.
    #[inline]
    pub fn get(self, range: std::ops::Range<usize>) -> Option<Self> {
        if range.end > self.len() {
            return None;
        }
        let new_len = range.len();
        unsafe {
            // SAFETY:
            //
            // Contract from `ptr::add`: If the computed offset is non-zero, then self
            // must be derived from a pointer to some allocation, and the entire memory
            // range between self and the result must be in bounds of that allocation.
            // In particular, this range must not "wrap around" the edge of the address
            // space.
            //
            // Evidence: We take care to ensure to only get here if the `begin_offset`
            // (and a stronger condition: `begin_offset + len`) would be within `len()`
            // of the base pointer.
            //
            // Contract from `ptr::add`: The offset in bytes, count * size_of::<T>(),
            // computed on mathematical integers (without "wrapping around"), must fit
            // in an isize.
            //
            // Evidence: Allocation size in Rust, including those of the region backing
            // memory here specifically, may not exceed `isize::MAX` bytes.
            Some(match self {
                HostBuffer::Immutable(p) => HostBuffer::Immutable(ptr::slice_from_raw_parts(
                    p.byte_add(range.start).cast(),
                    new_len,
                )),
                HostBuffer::Mutable(p) => HostBuffer::Mutable(ptr::slice_from_raw_parts_mut(
                    p.byte_add(range.start).cast(),
                    new_len,
                )),
            })
        }
    }

    /// Pointer to a slice of the host memory.
    #[inline(always)]
    pub fn ptr(self) -> *const [u8] {
        match self {
            HostBuffer::Immutable(p) => p,
            HostBuffer::Mutable(p) => p,
        }
    }

    /// Mutble pointer to a slice of the host memory.
    #[inline(always)]
    pub fn ptr_mut(self) -> *mut [u8] {
        match self {
            HostBuffer::Immutable(p) => {
                debug_assert!(false, "ptr_mut, but buffer is immutable");
                p.cast_mut()
            }
            HostBuffer::Mutable(p) => p,
        }
    }
}

unsafe impl HostMemoryObject for HostBuffer {
    fn host(self) -> HostBuffer {
        self
    }
}

/// Memory region for bounds checking and address translation
#[derive(Eq, PartialEq, Clone)]
pub struct MemoryRegion {
    pub host: HostBuffer,
    /// start virtual address
    pub vm_addr: u64,
    /// Size of regular gaps as bit shift (63 means this region is continuous)
    vm_gap_shift: u8,
    /// User defined payload for the [AccessViolationHandler]
    pub access_violation_handler_payload: Option<u16>,
}

impl MemoryRegion {
    /// Create a VM memory region with host `address` pointing to a `len` bytes of data.
    ///
    /// This region will be made available in the guest at `vm_addr`.
    fn new_internal(host: HostBuffer, vm_addr: u64, vm_gap_size: u64) -> Self {
        let mut vm_gap_shift = (std::mem::size_of::<u64>() as u8)
            .saturating_mul(8)
            .saturating_sub(1);
        if vm_gap_size > 0 {
            vm_gap_shift = vm_gap_shift.saturating_sub(vm_gap_size.leading_zeros() as u8);
            debug_assert_eq!(Some(vm_gap_size), 1_u64.checked_shl(vm_gap_shift as u32));
        };
        MemoryRegion {
            host,
            vm_addr,
            vm_gap_shift,
            access_violation_handler_payload: None,
        }
    }

    /// Creates a new, empty `MemoryRegion`.
    ///
    /// This does not require to provide any backing host memory.
    pub fn new_empty(vm_addr: u64) -> Self {
        const EMPTY: &[u8] = &[];
        Self::new_internal((&raw const *EMPTY).host(), vm_addr, 0)
    }

    /// Creates a new `MemoryRegion` backed by the provided host memory.
    ///
    /// The backing memory must remain allocated for the duration of the returned `MemoryRegion`.
    pub fn new<HO: HostMemoryObject>(host: HO, vm_addr: u64) -> Self {
        Self::new_internal(host.host(), vm_addr, 0)
    }

    /// Creates a new gapped `MemoryRegion` backed by the provided host memory.
    ///
    /// The backing memory must remain allocated for the duration of the returned `MemoryRegion`.
    pub fn new_gapped<HO: HostMemoryObject>(host: HO, vm_addr: u64, vm_gap_size: u64) -> Self {
        Self::new_internal(host.host(), vm_addr, vm_gap_size)
    }

    /// Redirect this memory region to a different location in host memory.
    ///
    /// Depending on whether `HO` is mutable, the writability of the region is adjusted as well.
    ///
    /// # Safety
    ///
    /// If this `MemoryRegion` is a part of a [`MemoryMapping`] then, after redirection, this region
    /// must adhere to all the same contracts as the `MemoryRegion`s used for
    /// [`MemoryMapping::replace_region`].
    pub unsafe fn redirect<HO: HostMemoryObject>(&mut self, host: HO) {
        self.host = host.host();
    }

    /// Ensure that this memory region is immutable.
    pub fn make_immutable(&mut self) {
        unsafe {
            // SAFETY:
            // Contract from `MemoryRegion::redirect`: memory region must be live for
            // the duration of the mapping.
            //
            // Evidence: Since we aren't changing where the host buffer is pointing at,
            // the condition must already have been satisfied at the time this function was called
            // and thus remains satisfied.
            //
            // Contract from `MemoryRegion::redirect`: For `MemoryRegions` marked writable...
            //
            // Evidence: Memory region is no longer writable.
            self.redirect(self.host_buffer().immutable());
        }
    }

    /// Returns the vm address space covered by this MemoryRegion
    pub fn vm_addr_range(&self) -> Range<u64> {
        let bytes = self.len() as u64;
        if self.vm_gap_shift == 63 {
            self.vm_addr..self.vm_addr.saturating_add(bytes)
        } else {
            self.vm_addr..self.vm_addr.saturating_add(bytes.saturating_mul(2))
        }
    }

    /// Return the raw slice to the host memory that this memory region points at.
    ///
    /// This can be used to construct a new memory region.
    pub fn host_buffer(&self) -> HostBuffer {
        self.host
    }

    /// Length of this memory region in bytes.
    pub fn len(&self) -> usize {
        self.host.len()
    }

    /// Is the length of this memory region 0 bytes?
    pub fn is_empty(&self) -> bool {
        self.host.is_empty()
    }

    /// Return the `gap_size` with which the memory region has been constructed.
    pub fn gap_size(&self) -> u64 {
        if self.vm_gap_shift == 63 {
            0
        } else {
            1 << self.vm_gap_shift
        }
    }

    /// Convert a virtual machine address into a host slice.
    ///
    /// The returned slice will have exactly `len` bytes. If the provided `vm_addr` does not
    /// correlate to a valid subslice of this region, a `None` will be returned.
    #[inline]
    pub(crate) fn vm_to_host_buffer(&self, vm_addr: u64, len: u64) -> Option<HostBuffer> {
        // This can happen if a region starts at an offset from the base region
        // address, eg with rodata regions if config.optimize_rodata = true, see
        // Elf::get_ro_region.
        if vm_addr < self.vm_addr {
            return None;
        }

        let begin_offset = vm_addr.saturating_sub(self.vm_addr);
        if self.vm_gap_shift == 63 {
            // fast path for non-gapped regions
            if let Some(end_offset) = begin_offset.checked_add(len) {
                return self.host.get(begin_offset as usize..end_offset as usize);
            }
            return None;
        }

        let is_in_gap = (begin_offset
            .checked_shr(self.vm_gap_shift as u32)
            .unwrap_or(0)
            & 1)
            == 1;
        let gap_mask = (-1i64).checked_shl(self.vm_gap_shift as u32).unwrap_or(0) as u64;
        let gapped_offset =
            (begin_offset & gap_mask).checked_shr(1).unwrap_or(0) | (begin_offset & !gap_mask);
        if let Some(end_offset) = gapped_offset.checked_add(len) {
            if !is_in_gap {
                return self.host.get(gapped_offset as usize..end_offset as usize);
            }
        }
        None
    }
}

impl fmt::Debug for MemoryRegion {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let vm_addr = self.vm_addr_range();
        let (host_addr, len, writable) = match self.host {
            HostBuffer::Immutable(p) => (p.addr() as u64, p.len() as u64, false),
            HostBuffer::Mutable(p) => (p.addr() as u64, p.len() as u64, true),
        };
        write!(
            f,
            "host_addr: {:#x?}-{:#x?}, vm_addr: {:#x?}-{:#x?}, len: {}, writable: {}, payload {:?}",
            host_addr,
            host_addr.saturating_add(len),
            vm_addr.start,
            vm_addr.end,
            len,
            writable,
            self.access_violation_handler_payload,
        )
    }
}

impl std::cmp::PartialOrd for MemoryRegion {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl std::cmp::Ord for MemoryRegion {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.vm_addr.cmp(&other.vm_addr)
    }
}

/// Type of memory access
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum AccessType {
    /// Read
    Load,
    /// Write
    Store,
}

impl std::fmt::Display for AccessType {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        f.write_str(match self {
            Self::Load => "reading",
            Self::Store => "writing",
        })
    }
}

/// Memory mapping based on eytzinger search.
pub struct UnalignedMemoryMapping {
    /// Common parts
    pub regions: Box<[MemoryRegion]>,
    /// Regions vm_addr fields in Eytzinger order
    region_addresses: Box<[u64]>,
    /// Converts the Eytzinger order back to the original order
    region_index_lookup: Box<[usize]>,
    /// Cache of the last `MappingCache::SIZE` vm_addr => region_index lookups
    cache: UnsafeCell<MappingCache>,
}

impl fmt::Debug for UnalignedMemoryMapping {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("UnalignedMemoryMapping")
            .field("regions", &self.regions)
            .field("cache", &self.cache)
            .finish()
    }
}

impl UnalignedMemoryMapping {
    fn construct_eytzinger_order(&mut self, mut in_index: usize, out_index: usize) -> usize {
        if out_index >= self.regions.len() {
            return in_index;
        }
        in_index =
            self.construct_eytzinger_order(in_index, out_index.saturating_mul(2).saturating_add(1));
        self.region_addresses[out_index] = self.regions[in_index].vm_addr;
        self.region_index_lookup[out_index] = in_index;
        self.construct_eytzinger_order(
            in_index.saturating_add(1),
            out_index.saturating_mul(2).saturating_add(2),
        )
    }

    /// Create an uninitialized UnalignedMapping
    ///
    /// # Safety
    ///
    /// Refer to [`MemoryMapping::new_uninitialized`].
    pub unsafe fn new_uninitialized(regions: Vec<MemoryRegion>) -> Self {
        let number_of_regions = regions.len();
        Self {
            regions: regions.into_boxed_slice(),
            region_addresses: vec![0; number_of_regions].into_boxed_slice(),
            region_index_lookup: vec![0; number_of_regions].into_boxed_slice(),
            cache: UnsafeCell::new(MappingCache::new()),
        }
    }

    /// Creates a new MemoryMapping structure from the given regions
    ///
    /// # Safety
    ///
    /// Refer to [`MemoryMapping::new_uninitialized`].
    pub unsafe fn new(regions: Vec<MemoryRegion>) -> Result<Self, EbpfError> {
        let mut mapping = Self::new_uninitialized(regions);
        mapping.initialize()?;
        Ok(mapping)
    }

    /// Initialize the memory mapping
    pub fn initialize(&mut self) -> Result<(), EbpfError> {
        self.regions.sort();
        let number_of_regions = self.regions.len();
        for index in 1..number_of_regions {
            let first = &self.regions[index.saturating_sub(1)];
            let second = &self.regions[index];
            if first.vm_addr_range().end > second.vm_addr {
                return Err(EbpfError::InvalidMemoryRegion(index));
            }
        }

        self.construct_eytzinger_order(0, 0);
        Ok(())
    }

    /// Returns the `MemoryRegion` which may contain the given address.
    #[allow(clippy::arithmetic_side_effects)]
    #[inline(always)]
    pub fn find_region(&self, vm_addr: u64) -> Option<(usize, &MemoryRegion)> {
        // Safety:
        // &mut references to the mapping cache are only created internally from methods that do not
        // invoke each other. UnalignedMemoryMapping is !Sync, so the cache reference below is
        // guaranteed to be unique.
        let cache = unsafe { &mut *self.cache.get() };
        if let Some(index) = cache.find(vm_addr) {
            // Safety:
            // Cached index, we validated it before caching it. See the corresponding safety section
            // in the miss branch.
            Some((index, unsafe { self.regions.get_unchecked(index) }))
        } else {
            let mut index = 1;
            while index <= self.region_addresses.len() {
                // Safety:
                // we start the search at index=1 and in the loop condition check
                // for index <= len, so bound checks can be avoided
                index = (index << 1)
                    + unsafe { *self.region_addresses.get_unchecked(index - 1) <= vm_addr }
                        as usize;
            }
            index >>= index.trailing_zeros() + 1;
            if index == 0 {
                return None;
            }
            // Safety:
            // we check for index==0 above, and by construction if we get here index
            // must be contained in region
            index = unsafe { *self.region_index_lookup.get_unchecked(index - 1) };
            let region = unsafe { self.regions.get_unchecked(index) };
            cache.insert(region.vm_addr_range(), index);
            Some((index, region))
        }
    }

    /// Replaces the `MemoryRegion` at the given index
    ///
    /// # Safety
    ///
    /// Refer to [`MemoryMapping::new_uninitialized`].
    #[inline(always)]
    pub unsafe fn replace_region(
        &mut self,
        index: usize,
        region: MemoryRegion,
    ) -> Result<(), EbpfError> {
        self.regions[index] = region;
        self.cache.get_mut().flush();
        Ok(())
    }
}

/// Memory mapping that uses the upper half of an address to identify the
/// underlying memory region.
#[derive(Debug)]
pub struct AlignedMemoryMapping {
    pub regions: Vec<MemoryRegion>,
    virtual_address_bits: u32,
}

impl AlignedMemoryMapping {
    /// Creates a new initialized MemoryMapping structure from the given regions
    ///
    /// # Safety
    ///
    /// Refer to [`MemoryMapping::new_uninitialized`].
    pub unsafe fn new(regions: Vec<MemoryRegion>, region_size: usize) -> Result<Self, EbpfError> {
        let mut mapping = Self::new_uninitialized(regions, region_size);
        mapping.initialize()?;
        Ok(mapping)
    }

    /// Create an uninitialized MemoryMapping
    ///
    /// # Safety
    ///
    /// Refer to [`MemoryMapping::new_uninitialized`].
    pub unsafe fn new_uninitialized(regions: Vec<MemoryRegion>, region_size: usize) -> Self {
        debug_assert!(region_size.is_multiple_of(2));
        let virtual_address_bits = region_size.trailing_zeros();
        Self {
            regions,
            virtual_address_bits,
        }
    }

    /// Initialize the memory mapping by sorting its regions and filling gaps
    pub fn initialize(&mut self) -> Result<(), EbpfError> {
        static EMPTY_SLICE: &[u8] = &[];
        self.regions.sort();
        let mut expected_region_index = 0;
        while expected_region_index < self.regions.len() {
            let actual_region_index = self
                .regions
                .get(expected_region_index)
                .unwrap()
                .vm_addr
                .checked_shr(self.virtual_address_bits)
                .unwrap_or(0) as usize;
            if actual_region_index > expected_region_index {
                self.regions.insert(
                    expected_region_index,
                    MemoryRegion::new(
                        &raw const *EMPTY_SLICE,
                        (expected_region_index as u64)
                            .checked_shl(self.virtual_address_bits)
                            .unwrap_or(u64::MAX),
                    ),
                );
            } else if actual_region_index < expected_region_index {
                return Err(EbpfError::InvalidMemoryRegion(actual_region_index));
            }
            expected_region_index = expected_region_index.saturating_add(1);
        }

        Ok(())
    }

    /// Returns the `MemoryRegion` which may contain the given address.
    #[inline(always)]
    pub fn find_region(&self, vm_addr: u64) -> Option<(usize, &MemoryRegion)> {
        let index = vm_addr.wrapping_shr(self.virtual_address_bits) as usize;
        if index < self.regions.len() {
            // Safety: bounds check above
            let region = unsafe { self.regions.get_unchecked(index) };
            return Some((index, region));
        }
        None
    }

    /// Replaces the `MemoryRegion` at the given index
    ///
    /// # Safety
    ///
    /// Refer to [`MemoryMapping::new_uninitialized`].
    #[inline(always)]
    pub unsafe fn replace_region(
        &mut self,
        index: usize,
        region: MemoryRegion,
    ) -> Result<(), EbpfError> {
        let begin_index = region
            .vm_addr
            .checked_shr(self.virtual_address_bits)
            .unwrap_or(0) as usize;
        let end_index = region
            .vm_addr
            .saturating_add((region.len() as u64).saturating_sub(1))
            .checked_shr(self.virtual_address_bits)
            .unwrap_or(0) as usize;
        if begin_index != index || end_index != index {
            return Err(EbpfError::InvalidMemoryRegion(index));
        }
        self.regions[index] = region;
        Ok(())
    }
}

/// Common parts of [UnalignedMemoryMapping] and [AlignedMemoryMapping]
pub struct MemoryMapping {
    /// Access violation handler
    access_violation_handler: AccessViolationHandler,
    max_call_depth: i64,
    stack_frame_size: i64,
    /// Executable sbpf_version
    sbpf_version: SBPFVersion,
    initialized: bool,
    pub ty: MemoryMappingType,
}

impl fmt::Debug for MemoryMapping {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("MemoryMapping")
            .field("max_call_depth", &self.max_call_depth)
            .field("stack_frame_size", &self.stack_frame_size)
            .field("sbpf_version", &self.sbpf_version)
            .field("ty", &self.ty)
            .finish()
    }
}

/// Maps virtual memory to host memory.
#[derive(Debug)]
pub enum MemoryMappingType {
    /// Aligned memory mapping which uses the upper half of an address to
    /// identify the underlying memory region.
    Aligned(AlignedMemoryMapping),
    /// Memory mapping that allows mapping unaligned memory regions.
    Unaligned(UnalignedMemoryMapping),
}

impl MemoryMapping {
    /// Creates a new memory mapping.
    ///
    /// Uses aligned or unaligned memory mapping depending on the value of
    /// `config.aligned_memory_mapping=true`.
    ///
    /// # Safety
    ///
    /// In addition to the requirements of [`MemoryMapping::new_uninitialized`], the provided
    /// `access_violation_handler` must return with its [`MemoryRegion`] unmodified, or initialized
    /// to another equally correct [`MemoryRegion`] as described in the safety invariants for
    /// `new_uninitialized`.
    pub unsafe fn new_with_access_violation_handler(
        regions: Vec<MemoryRegion>,
        config: &Config,
        sbpf_version: SBPFVersion,
        access_violation_handler: AccessViolationHandler,
    ) -> Result<Self, EbpfError> {
        let mut mapping =
            Self::new_uninitialized(regions, config, sbpf_version, access_violation_handler);
        mapping.initialize()?;
        Ok(mapping)
    }

    /// Creates an unitialized memory mapping
    ///
    /// # Safety
    ///
    /// The memory pointed to by the [`MemoryRegion`]s must point to a valid object live for the
    /// duration of this `MemoryMapping`.
    ///
    /// For `MemoryRegion`s marked writable, the memory pointed to by the memory region must accept
    /// arbitrary bytes being overwritten without it resulting in unsoundness (due to e.g. broken
    /// internal type invariants.)
    pub unsafe fn new_uninitialized(
        regions: Vec<MemoryRegion>,
        config: &Config,
        sbpf_version: SBPFVersion,
        access_violation_handler: AccessViolationHandler,
    ) -> Self {
        let ty = if sbpf_version >= SBPFVersion::V4 || config.aligned_memory_mapping {
            MemoryMappingType::Aligned(AlignedMemoryMapping::new_uninitialized(
                regions,
                config.aligned_region_size,
            ))
        } else {
            debug_assert!(
                sbpf_version <= SBPFVersion::V3,
                "SBPFv4 and later versions do not support unaligned memory"
            );
            MemoryMappingType::Unaligned(UnalignedMemoryMapping::new_uninitialized(regions))
        };

        Self {
            access_violation_handler: Box::new(access_violation_handler),
            max_call_depth: config.max_call_depth as i64,
            stack_frame_size: config.stack_frame_size as i64,
            sbpf_version,
            initialized: false,
            ty,
        }
    }

    /// Creates a new memory mapping for tests and benches.
    ///
    /// `access_violation_handler` defaults to a function which always returns an error.
    ///
    /// # Safety
    ///
    /// Refer to [`MemoryMapping::new_uninitialized`].
    pub unsafe fn new(
        regions: Vec<MemoryRegion>,
        config: &Config,
        sbpf_version: SBPFVersion,
    ) -> Result<Self, EbpfError> {
        Self::new_with_access_violation_handler(
            regions,
            config,
            sbpf_version,
            Box::new(default_access_violation_handler),
        )
    }

    /// Map virtual memory to host memory.
    #[inline(always)]
    pub fn map(
        &self,
        access_type: AccessType,
        vm_addr: u64,
        len: u64,
    ) -> StableResult<HostBuffer, EbpfError> {
        debug_assert!(self.initialized);
        let region = self.find_region(vm_addr).map(|(_index, region)| region);
        match region {
            Some(region)
                if region.host_buffer().is_mutable() || access_type != AccessType::Store =>
            {
                if let Some(host_buffer) = region.vm_to_host_buffer(vm_addr, len) {
                    return StableResult::Ok(host_buffer);
                }
            }
            _ => (),
        }
        StableResult::Err(self.generate_access_violation_for(region, access_type, vm_addr, len))
    }

    /// Map virtual memory to host memory and potentially call the [AccessViolationHandler].
    ///
    /// This requires the [MemoryMapping] to be mutable and
    /// can cause previously translated addresses to become invalid.
    #[inline(always)]
    pub fn map_with_access_violation_handler(
        &mut self,
        access_type: AccessType,
        vm_addr: u64,
        len: u64,
    ) -> StableResult<HostBuffer, EbpfError> {
        debug_assert!(self.initialized);
        match self.find_region(vm_addr) {
            Some((_index, region))
                if region.host_buffer().is_mutable() || access_type != AccessType::Store =>
            {
                if let Some(host_buffer) = region.vm_to_host_buffer(vm_addr, len) {
                    return StableResult::Ok(host_buffer);
                }
            }
            _ => (),
        }
        // The slow path is out of line, so that the code in there doesn't make the callers of the
        // fast path save and restore registers they otherwise do not need to. Note, that a single
        // call site for the cold path matters. Split it up and LLVM merges their results with the
        // fast path's through the stack.
        self.invoke_access_violation_handler_then_map(access_type, vm_addr, len)
    }

    // `#[cold]`, `#[inline(never)]` have been experimentally determined to improve mapping function
    // throughput.
    // In the future using a `rust-cold` calling convention would help this further.
    #[cold]
    #[inline(never)]
    fn invoke_access_violation_handler_then_map(
        &mut self,
        access_type: AccessType,
        vm_addr: u64,
        len: u64,
    ) -> StableResult<HostBuffer, EbpfError> {
        let regions = self.get_regions();
        let Some((region_index, region)) = self.find_region(vm_addr) else {
            debug_assert!(self.find_region(vm_addr).is_none());
            return StableResult::Err(self.generate_access_violation_for(
                None,
                access_type,
                vm_addr,
                len,
            ));
        };
        let mut region = region.clone();
        let max_len = regions
            .get(region_index.saturating_add(1))
            .map_or(u64::MAX, |next_region| next_region.vm_addr)
            .saturating_sub(region.vm_addr);
        (self.access_violation_handler)(&mut region, max_len, access_type, vm_addr, len);
        if region.host_buffer().is_mutable() || access_type != AccessType::Store {
            if let Some(host_buffer) = region.vm_to_host_buffer(vm_addr, len) {
                if let Err(err) = unsafe { self.replace_region(region_index, region) } {
                    return StableResult::Err(err);
                }
                return StableResult::Ok(host_buffer);
            }
        }
        // The handler did not change the region in the mapping, so the original one still applies.
        let region = self.get_regions().get(region_index);
        StableResult::Err(self.generate_access_violation_for(region, access_type, vm_addr, len))
    }

    /// Loads `size_of::<T>()` bytes at the given guest address without invoking the access_violation_handler.
    #[inline]
    pub fn load_first_attempt<T: Pod + Into<u64>>(&mut self, vm_addr: u64) -> ProgramResult {
        let len = mem::size_of::<T>() as u64;
        debug_assert!(len <= mem::size_of::<u64>() as u64);
        debug_assert!(self.initialized);
        let ptr = match self.map(AccessType::Load, vm_addr, len) {
            StableResult::Err(e) => return ProgramResult::Err(e),
            StableResult::Ok(buf) => buf.ptr(),
        };
        ProgramResult::Ok(unsafe { ptr::read_unaligned::<T>(ptr.cast()).into() })
    }

    /// Stores `value` at the given guest address without invoking the access_violation_handler.
    #[inline]
    pub fn store_first_attempt<T: Pod>(&mut self, value: T, vm_addr: u64) -> ProgramResult {
        let len = mem::size_of::<T>() as u64;
        debug_assert!(len <= mem::size_of::<u64>() as u64);
        debug_assert!(self.initialized);
        let ptr = match self.map(AccessType::Store, vm_addr, len) {
            StableResult::Err(e) => return ProgramResult::Err(e),
            StableResult::Ok(buf) => buf.ptr_mut(),
        };
        unsafe {
            ptr::write_unaligned::<T>(ptr.cast(), value);
        }
        StableResult::Ok(0)
    }

    /// Invokes access_violation_handler then loads `size_of::<T>()` bytes at the given guest address.
    #[cold]
    #[inline(never)]
    pub fn load_second_attempt<T: Pod + Into<u64>>(&mut self, vm_addr: u64) -> ProgramResult {
        let len = mem::size_of::<T>() as u64;
        debug_assert!(len <= mem::size_of::<u64>() as u64);
        debug_assert!(self.initialized);
        let ptr =
            match self.invoke_access_violation_handler_then_map(AccessType::Load, vm_addr, len) {
                StableResult::Err(e) => return ProgramResult::Err(e),
                StableResult::Ok(buf) => buf.ptr(),
            };
        ProgramResult::Ok(unsafe { ptr::read_unaligned::<T>(ptr.cast()).into() })
    }

    /// Invokes access_violation_handler then stores `value` at the given guest address.
    #[cold]
    #[inline(never)]
    pub fn store_second_attempt<T: Pod>(&mut self, value: T, vm_addr: u64) -> ProgramResult {
        let len = mem::size_of::<T>() as u64;
        debug_assert!(len <= mem::size_of::<u64>() as u64);
        debug_assert!(self.initialized);
        let ptr =
            match self.invoke_access_violation_handler_then_map(AccessType::Store, vm_addr, len) {
                StableResult::Err(e) => return ProgramResult::Err(e),
                StableResult::Ok(buf) => buf.ptr_mut(),
            };
        unsafe {
            ptr::write_unaligned::<T>(ptr.cast(), value);
        }
        StableResult::Ok(0)
    }

    /// Returns the `MemoryRegion` which may contain the given address.
    #[inline(always)]
    pub fn find_region(&self, vm_addr: u64) -> Option<(usize, &MemoryRegion)> {
        debug_assert!(self.initialized);
        match &self.ty {
            MemoryMappingType::Aligned(inner) => inner.find_region(vm_addr),
            MemoryMappingType::Unaligned(inner) => inner.find_region(vm_addr),
        }
    }

    /// Returns the `MemoryRegion`s in this mapping.
    #[inline(always)]
    pub fn get_regions(&self) -> &[MemoryRegion] {
        match &self.ty {
            MemoryMappingType::Aligned(inner) => &inner.regions,
            MemoryMappingType::Unaligned(inner) => &inner.regions,
        }
    }

    /// Returns the [`MemoryRegion`]s as mutable.
    ///
    /// Modifying the regions might break the initialization constraints, so this function
    /// uninitializes the mapping. The memory mappings must be initialized
    /// again with [`Self::initialize`] before further use.
    pub fn get_regions_mut(&mut self) -> &mut [MemoryRegion] {
        self.initialized = false;

        let regions = match &mut self.ty {
            MemoryMappingType::Aligned(inner) => inner.regions.as_mut_slice(),
            MemoryMappingType::Unaligned(inner) => &mut inner.regions,
        };

        regions
    }

    /// Replaces the `MemoryRegion` at the given index
    ///
    /// # Safety
    ///
    /// Refer to [`MemoryMapping::new_uninitialized`].
    #[inline(always)]
    pub unsafe fn replace_region(
        &mut self,
        index: usize,
        region: MemoryRegion,
    ) -> Result<(), EbpfError> {
        debug_assert!(self.initialized);
        let regions = self.get_regions();
        let next_region_start = regions
            .get(index.saturating_add(1))
            .map_or(u64::MAX, |next_region| next_region.vm_addr);
        if index >= regions.len()
            || regions[index].vm_addr != region.vm_addr
            || region.vm_addr_range().end > next_region_start
        {
            return Err(EbpfError::InvalidMemoryRegion(index));
        }
        match &mut self.ty {
            MemoryMappingType::Aligned(inner) => inner.replace_region(index, region),
            MemoryMappingType::Unaligned(inner) => inner.replace_region(index, region),
        }
    }

    /// Initialize the MemoryMapping
    pub fn initialize(&mut self) -> Result<(), EbpfError> {
        let result = match &mut self.ty {
            MemoryMappingType::Aligned(inner) => inner.initialize(),
            MemoryMappingType::Unaligned(inner) => inner.initialize(),
        };
        self.initialized = result.is_ok();
        result
    }

    #[cold]
    #[inline(never)]
    fn generate_access_violation_for(
        &self,
        region: Option<&MemoryRegion>,
        access_type: AccessType,
        vm_addr: u64,
        len: u64,
    ) -> EbpfError {
        let stack_frame = (vm_addr as i64)
            .saturating_sub(ebpf::MM_STACK_START as i64)
            .checked_div(self.stack_frame_size)
            .unwrap_or(0);
        if !self.sbpf_version.manual_stack_frame_bump()
            && (-1..self.max_call_depth.saturating_add(1)).contains(&stack_frame)
        {
            EbpfError::StackAccessViolation(access_type, vm_addr, len, stack_frame)
        } else {
            let region_name = match vm_addr & (!ebpf::MM_BYTECODE_START.saturating_sub(1)) {
                _ if region.map(|r| r.vm_addr_range().contains(&vm_addr)) != Some(true) => {
                    "unallocated"
                }
                ebpf::MM_BYTECODE_START => "program",
                ebpf::MM_STACK_START => "stack",
                ebpf::MM_HEAP_START => "heap",
                ebpf::MM_INPUT_START => "input",
                _ => "allocated",
            };
            EbpfError::AccessViolation(access_type, vm_addr, len, region_name)
        }
    }
}

/// Fast, small linear cache used to speed up unaligned memory mapping.
#[derive(Debug)]
pub struct MappingCache {
    // The cached entries.
    entries: [(Range<u64>, usize); MappingCache::SIZE],
    // Index of the last accessed memory region.
    //
    // New entries are written backwards, so that find() can always scan
    // forward which is faster.
    head: usize,
}

impl MappingCache {
    // must be a power of two
    const SIZE: usize = 4;

    pub fn new() -> MappingCache {
        MappingCache {
            entries: array::from_fn(|_| (0..0, 0)),
            head: 0,
        }
    }

    #[inline]
    pub fn find(&self, vm_addr: u64) -> Option<usize> {
        for i in 0..Self::SIZE {
            let index = self.head.wrapping_add(i) % Self::SIZE;
            // Safety:
            // index is guaranteed to be between 0..Self::SIZE
            let (vm_range, region_index) = unsafe { self.entries.get_unchecked(index) };
            if vm_range.contains(&vm_addr) {
                return Some(*region_index);
            }
        }

        None
    }

    #[inline]
    pub fn insert(&mut self, vm_range: Range<u64>, region_index: usize) {
        self.head = self.head.wrapping_sub(1) % Self::SIZE;
        // Safety:
        // self.head is guaranteed to be between 0..Self::SIZE
        unsafe { *self.entries.get_unchecked_mut(self.head) = (vm_range, region_index) };
    }

    #[inline]
    pub fn flush(&mut self) {
        self.entries = array::from_fn(|_| (0..0, 0));
        self.head = 0;
    }
}

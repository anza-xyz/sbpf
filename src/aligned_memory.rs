//! Aligned memory

use std::{
    alloc::{alloc, alloc_zeroed, dealloc, handle_alloc_error, Layout},
    mem,
    ptr::NonNull,
};

/// Scalar types, aka "plain old data"
pub trait Pod: Copy {}

impl Pod for u8 {}
impl Pod for u16 {}
impl Pod for u32 {}
impl Pod for u64 {}
impl Pod for i8 {}
impl Pod for i16 {}
impl Pod for i32 {}
impl Pod for i64 {}

/// Provides u8 slices at a specified alignment
#[derive(Debug, PartialEq, Eq)]
pub struct AlignedMemory<const ALIGN: usize> {
    mem: AlignedVec<ALIGN>,
    zero_up_to_max_len: bool,
}

impl<const ALIGN: usize> AlignedMemory<ALIGN> {
    /// Returns a filled AlignedMemory by copying the given slice
    pub fn from_slice(data: &[u8]) -> Self {
        let max_len = data.len();
        let mut mem = AlignedVec::new(max_len, false);
        unsafe {
            // SAFETY: `mem` was allocated with `max_len` bytes
            core::ptr::copy_nonoverlapping(data.as_ptr(), mem.as_mut_ptr(), max_len);
            mem.set_len(max_len);
        }
        Self {
            mem,
            zero_up_to_max_len: false,
        }
    }

    /// Returns a new empty AlignedMemory with uninitialized preallocated memory
    pub fn with_capacity(max_len: usize) -> Self {
        let mem = AlignedVec::new(max_len, false);
        Self {
            mem,
            zero_up_to_max_len: false,
        }
    }

    /// Returns a new empty AlignedMemory with zero initialized preallocated memory
    pub fn with_capacity_zeroed(max_len: usize) -> Self {
        let mem = AlignedVec::new(max_len, true);
        Self {
            mem,
            zero_up_to_max_len: true,
        }
    }

    /// Returns a new filled AlignedMemory with zero initialized preallocated memory
    pub fn zero_filled(max_len: usize) -> Self {
        let mut mem = AlignedVec::new(max_len, true);
        // SAFETY: Bytes were zeroed
        unsafe {
            mem.set_len(max_len);
        }
        Self {
            mem,
            zero_up_to_max_len: true,
        }
    }

    /// Calculate memory size (allocated memory block and the size of [`AlignedMemory`] itself).
    pub fn mem_size(&self) -> usize {
        self.mem.capacity().saturating_add(mem::size_of::<Self>())
    }

    /// Get the length of the data
    pub fn len(&self) -> usize {
        self.mem.len()
    }

    /// Is the memory empty
    pub fn is_empty(&self) -> bool {
        self.mem.is_empty()
    }

    /// Get the current write index
    pub fn write_index(&self) -> usize {
        self.mem.len()
    }

    /// Get an aligned slice
    pub fn as_slice(&self) -> &[u8] {
        self.mem.as_slice()
    }

    /// Get an aligned mutable slice
    pub fn as_slice_mut(&mut self) -> &mut [u8] {
        self.mem.as_slice_mut()
    }

    /// Grows memory with `value` repeated `num` times starting at the `write_index`
    pub fn fill_write(&mut self, num: usize, value: u8) -> std::io::Result<()> {
        let (ptr, new_len) = self.mem.write_ptr_for(num).ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "aligned memory fill_write failed",
            )
        })?;

        if self.zero_up_to_max_len && value == 0 {
            // No action needed because up to `max_len` is zeroed and no shrinking is allowed
        } else {
            unsafe {
                core::ptr::write_bytes(ptr, value, num);
            }
        }
        unsafe {
            self.mem.set_len(new_len);
        }
        Ok(())
    }

    /// Write a generic type T into the memory.
    ///
    /// # Safety
    ///
    /// Unsafe since it assumes that there is enough capacity.
    pub unsafe fn write_unchecked<T: Pod>(&mut self, value: T) {
        let pos = self.mem.len();
        let new_len = pos.saturating_add(mem::size_of::<T>());
        debug_assert!(new_len <= self.mem.capacity());
        unsafe {
            self.mem.write_ptr().cast::<T>().write_unaligned(value);
            self.mem.set_len(new_len);
        }
    }

    /// Write a slice of bytes into the memory.
    ///
    /// # Safety
    ///
    /// Unsafe since it assumes that there is enough capacity.
    pub unsafe fn write_all_unchecked(&mut self, value: &[u8]) {
        let pos = self.mem.len();
        let new_len = pos.saturating_add(value.len());
        debug_assert!(new_len <= self.mem.capacity());
        core::ptr::copy_nonoverlapping(value.as_ptr(), self.mem.write_ptr(), value.len());
        self.mem.set_len(new_len);
    }
}

// Custom Clone impl is needed to ensure alignment. Derived clone would just
// clone self.mem and there would be no guarantee that the clone allocation is
// aligned.
impl<const ALIGN: usize> Clone for AlignedMemory<ALIGN> {
    fn clone(&self) -> Self {
        AlignedMemory::from_slice(self.as_slice())
    }
}

impl<const ALIGN: usize> std::io::Write for AlignedMemory<ALIGN> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let (ptr, new_len) = self.mem.write_ptr_for(buf.len()).ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "aligned memory fill_write failed",
            )
        })?;
        unsafe {
            core::ptr::copy_nonoverlapping(buf.as_ptr(), ptr, buf.len());
            self.mem.set_len(new_len);
        }
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl<const ALIGN: usize, T: AsRef<[u8]>> From<T> for AlignedMemory<ALIGN> {
    fn from(bytes: T) -> Self {
        AlignedMemory::from_slice(bytes.as_ref())
    }
}

/// Returns true if `ptr` is aligned to `align`.
pub fn is_memory_aligned(ptr: usize, align: usize) -> bool {
    ptr.checked_rem(align)
        .map(|remainder| remainder == 0)
        .unwrap_or(false)
}

/// Provides backing storage for [`AlignedMemory`]. Allocates a block of bytes with the
/// requested alignment, and can be increased in length up to the requested capacity.
struct AlignedVec<const ALIGN: usize> {
    ptr: NonNull<u8>,
    length: usize,
    capacity: usize,
}

impl<const ALIGN: usize> Drop for AlignedVec<ALIGN> {
    fn drop(&mut self) {
        if self.capacity == 0 {
            return;
        }
        let ptr = self.ptr.as_ptr();
        unsafe {
            // SAFETY: Layout is checked on construction
            let layout = Layout::from_size_align_unchecked(self.capacity, ALIGN);
            dealloc(ptr, layout);
        }
    }
}

impl<const A: usize> std::fmt::Debug for AlignedVec<A> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_list().entries(self.as_slice()).finish()
    }
}

impl<const A: usize> PartialEq for AlignedVec<A> {
    fn eq(&self, other: &Self) -> bool {
        self.as_slice() == other.as_slice()
    }
}

impl<const A: usize> Eq for AlignedVec<A> {}

impl<const ALIGN: usize> AlignedVec<ALIGN> {
    /// Allocates a [`Vec<u8>`] with the requested alignment.
    /// Ensure that the Vec is only dropped with the correct layout
    ///
    /// # Panics
    /// Panics if the requested size is incompatible with the requested alignment or if allocation fails.
    fn new(max_len: usize, zeroed: bool) -> Self {
        assert!(ALIGN != 0, "Alignment must not be zero");
        if max_len == 0 {
            return Self::empty();
        }
        unsafe {
            let layout = Layout::from_size_align(max_len, ALIGN).expect("invalid layout");
            // SAFETY: Layout is non-zero, and allocation errors are handled
            let ptr = if zeroed {
                alloc_zeroed(layout)
            } else {
                alloc(layout)
            };
            if ptr.is_null() {
                handle_alloc_error(layout);
            }
            Self {
                ptr: NonNull::new(ptr).unwrap_or_else(|| handle_alloc_error(layout)),
                length: 0,
                capacity: max_len,
            }
        }
    }

    fn as_slice(&self) -> &[u8] {
        unsafe { core::slice::from_raw_parts(self.ptr.as_ptr().cast_const(), self.length) }
    }

    fn as_slice_mut(&mut self) -> &mut [u8] {
        unsafe { core::slice::from_raw_parts_mut(self.ptr.as_ptr(), self.length) }
    }

    fn empty() -> Self {
        Self {
            // Create a dangling pointer
            // FIXME: Use `Layout::dangling_ptr` once Rust 1.95.0 is released
            ptr: NonNull::new(ALIGN as *mut u8).expect("alignment may not be zero"),
            length: 0,
            capacity: 0,
        }
    }

    fn as_mut_ptr(&mut self) -> *mut u8 {
        self.ptr.as_ptr()
    }

    /// Returns a pointer to the end of the current initialized length, i.e.
    /// `mem.as_mut_ptr().mem(self.len())`.
    /// Users must ensure that any writes to this pointer are in bounds of `capacity`
    fn write_ptr(&mut self) -> *mut u8 {
        unsafe { self.as_mut_ptr().add(self.len()) }
    }

    /// Similar to [`write_ptr`], but checks that there is room for the write.
    /// Returns (pointer, new_length)
    fn write_ptr_for(&mut self, bytes: usize) -> Option<(*mut u8, usize)> {
        let ptr = self.write_ptr();
        let new_len = self
            .len()
            .checked_add(bytes)
            .filter(|l| *l <= self.capacity())?;
        Some((ptr, new_len))
    }

    fn len(&self) -> usize {
        self.length
    }

    fn capacity(&self) -> usize {
        self.capacity
    }

    fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Set the length of the `AlignedVec`. The new length must be less than or equal to
    /// the capacity, and the memory must be initialized up to that length.
    /// The new length must also be greater than the previous length.
    unsafe fn set_len(&mut self, new_len: usize) {
        debug_assert!(
            new_len <= self.capacity,
            "attempted to grow AlignedVec beyond capacity"
        );
        debug_assert!(new_len > self.length, "attempted to shrink AlignedVec");
        self.length = new_len;
    }
}

#[allow(clippy::arithmetic_side_effects)]
#[cfg(test)]
mod tests {
    use {super::*, std::io::Write};

    fn do_test<const ALIGN: usize>() {
        let mut aligned_memory = AlignedMemory::<ALIGN>::with_capacity(10);
        let ptr = aligned_memory.mem.as_mut_ptr();
        assert_eq!(
            ptr.addr() & (ALIGN - 1),
            0,
            "memory is not correctly aligned"
        );

        assert_eq!(aligned_memory.write(&[42u8; 1]).unwrap(), 1);
        assert_eq!(aligned_memory.write(&[42u8; 9]).unwrap(), 9);
        assert_eq!(aligned_memory.as_slice(), &[42u8; 10]);
        assert_eq!(aligned_memory.write(&[42u8; 0]).unwrap(), 0);
        assert_eq!(aligned_memory.as_slice(), &[42u8; 10]);
        aligned_memory.write(&[42u8; 1]).unwrap_err();
        assert_eq!(aligned_memory.as_slice(), &[42u8; 10]);
        aligned_memory.as_slice_mut().copy_from_slice(&[84u8; 10]);
        assert_eq!(aligned_memory.as_slice(), &[84u8; 10]);

        let mut aligned_memory = AlignedMemory::<ALIGN>::with_capacity_zeroed(10);
        aligned_memory.fill_write(5, 0).unwrap();
        aligned_memory.fill_write(2, 1).unwrap();
        assert_eq!(aligned_memory.write(&[2u8; 3]).unwrap(), 3);
        assert_eq!(aligned_memory.as_slice(), &[0, 0, 0, 0, 0, 1, 1, 2, 2, 2]);
        aligned_memory.fill_write(1, 3).unwrap_err();
        aligned_memory.write(&[4u8; 1]).unwrap_err();
        assert_eq!(aligned_memory.as_slice(), &[0, 0, 0, 0, 0, 1, 1, 2, 2, 2]);

        let aligned_memory = AlignedMemory::<ALIGN>::zero_filled(10);
        assert_eq!(aligned_memory.len(), 10);
        assert_eq!(aligned_memory.as_slice(), &[0u8; 10]);

        let mut aligned_memory = AlignedMemory::<ALIGN>::with_capacity_zeroed(15);
        unsafe {
            aligned_memory.write_unchecked::<u8>(42);
            assert_eq!(aligned_memory.len(), 1);
            aligned_memory.write_unchecked::<u64>(0xCAFEBADDDEADCAFE);
            assert_eq!(aligned_memory.len(), 9);
            aligned_memory.fill_write(3, 0).unwrap();
            aligned_memory.write_all_unchecked(b"foo");
            assert_eq!(aligned_memory.len(), 15);
        }
        let mem = aligned_memory.as_slice();
        assert_eq!(mem[0], 42);
        assert_eq!(
            unsafe {
                core::ptr::read_unaligned::<u64>(mem[1..1 + mem::size_of::<u64>()].as_ptr().cast())
            },
            0xCAFEBADDDEADCAFE
        );
        assert_eq!(&mem[1 + mem::size_of::<u64>()..][..3], &[0, 0, 0]);
        assert_eq!(&mem[1 + mem::size_of::<u64>() + 3..], b"foo");
    }

    #[test]
    fn test_aligned_memory() {
        do_test::<1>();
        do_test::<16>();
        do_test::<32768>();
    }

    #[cfg(debug_assertions)]
    #[test]
    #[should_panic(expected = "<= self.mem.capacity()")]
    fn test_write_unchecked_debug_assert() {
        let mut aligned_memory = AlignedMemory::<8>::with_capacity(15);
        unsafe {
            aligned_memory.write_unchecked::<u64>(42);
            aligned_memory.write_unchecked::<u64>(24);
        }
    }

    #[cfg(debug_assertions)]
    #[test]
    #[should_panic(expected = "<= self.mem.capacity()")]
    fn test_write_all_unchecked_debug_assert() {
        let mut aligned_memory = AlignedMemory::<8>::with_capacity(5);
        unsafe {
            aligned_memory.write_all_unchecked(b"foo");
            aligned_memory.write_all_unchecked(b"bar");
        }
    }
}

// Copyright 2022 Solana Maintainers <maintainers@solana.com>
//
// Licensed under the Apache License, Version 2.0 <http://www.apache.org/licenses/LICENSE-2.0> or
// the MIT license <http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

#![cfg_attr(target_os = "windows", allow(dead_code))]

use std::marker::PhantomData;
use std::ops::Range;
use std::ptr::NonNull;
use std::sync::{Arc, LazyLock, Mutex};

use crate::error::EbpfError;

#[cfg(not(target_os = "windows"))]
extern crate libc;
#[cfg(not(target_os = "windows"))]
use libc::c_void;

#[cfg(target_os = "windows")]
use winapi::{
    ctypes::c_void,
    shared::minwindef,
    um::{
        errhandlingapi::GetLastError,
        memoryapi::{VirtualAlloc, VirtualFree, VirtualProtect},
        sysinfoapi::{GetSystemInfo, SYSTEM_INFO},
        winnt,
    },
};

/// A free list for managing memory allocations of a fixed size.
struct FreeList {
    /// Pool of free blocks awaiting reuse.
    mem: Mutex<Vec<Pages>>,
    /// The size of each memory block.
    size: usize,
}

impl FreeList {
    /// Create a new free list with the specified size.
    ///
    /// This does not allocate any memory blocks; they are allocated lazily as needed.
    fn new(size: usize) -> Self {
        Self {
            mem: Mutex::new(Vec::new()),
            size,
        }
    }

    /// Allocate a memory block of the configured size.
    ///
    /// If a free block is available, it is reused; otherwise, a new block is allocated. [`Pages`]
    /// allocated through this method return to the pool when dropped.
    ///
    /// Returned memory has read-write permissions and may contain arbitrary
    /// bytes left over from a previous owner; the caller should not assume
    /// any particular contents.
    fn alloc(&self) -> Pages {
        let pages = { self.mem.lock().unwrap_or_else(|e| e.into_inner()).pop() };
        let mut pages = pages.unwrap_or_else(|| Pages::new(self.size).expect("allocation failed"));
        pages.pooled = true;
        pages
    }

    /// Add [`Pages`] to the list.
    ///
    /// The memory being inserted is expected to be read-write across the entire accessible range.
    fn free(&self, pages: Pages) {
        /// The threshold for discarding physical backing from returned memory.
        ///
        /// Allocations at or above 128 MiB are uncommon, so drop their
        /// resident pages when they are returned to the pool.
        const MADV_DONTNEED_THRESHOLD: usize = 1024 * 1024 * 128; // 128 MiB

        if pages.len != self.size {
            panic!("size mismatch: expected {}, got {}", self.size, pages.len);
        }

        if self.size >= MADV_DONTNEED_THRESHOLD {
            // SAFETY: `madvise` has no soundness invariants with the arguments used here.
            if let Err(e) = unsafe { madvise(pages.raw.as_ptr(), pages.len, Advice::DontNeed) } {
                log::error!("FreeList: unable to advise returned allocation: {e}");
            }
        }

        self.mem
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push(pages);
    }
}

/// Minimum allocation size for a bucket.
const BUCKET_MIN: usize = 1024 * 128; // 128 KiB
/// Maximum allocation size for a bucket.
const BUCKET_MAX: usize = 1024 * 1024 * 256; // 256 MiB
/// Number of buckets in the free list.
const BUCKET_COUNT: usize =
    (BUCKET_MAX.trailing_zeros() - BUCKET_MIN.trailing_zeros()) as usize + 1;

const _: () = assert!(BUCKET_MIN.is_power_of_two());
const _: () = assert!(BUCKET_MAX.is_power_of_two());
const _: () = assert!(BUCKET_MIN <= BUCKET_MAX);
const _: () = assert!(BUCKET_MAX == BUCKET_MIN * (1 << (BUCKET_COUNT - 1)));

/// A free list that uses a bucketed strategy to manage memory
/// allocations of varying sizes.
///
/// Buckets are organized by power-of-two size, with the smallest
/// bucket being [`BUCKET_MIN`] and the largest being [`BUCKET_MAX`].
///
/// Allocations will be rounded up to the nearest power-of-two size
/// and stored in the corresponding bucket.
///
/// Returned blocks remain cached in the process-global pool and are not
/// released back to the OS during normal operation. This intentionally trades
/// higher retained RSS after peak load for fewer mmap/munmap calls during JIT
/// churn.
///
/// This is safe to use in a multi-threaded context -- locks are
/// sharded per bucket.
struct BucketedFreeList {
    buckets: [FreeList; BUCKET_COUNT],
}

impl BucketedFreeList {
    /// Construct an empty pool with one bucket per power-of-two size class.
    #[expect(clippy::arithmetic_side_effects)]
    fn new() -> Self {
        Self {
            buckets: core::array::from_fn(|i| FreeList::new(BUCKET_MIN * (1 << i))),
        }
    }

    /// Round up the requested size to the nearest power-of-two
    /// and determine the corresponding bucket index.
    #[inline]
    #[expect(clippy::arithmetic_side_effects)]
    fn bucket_idx(size: usize) -> usize {
        let bucket_bits = usize::BITS - (size.max(BUCKET_MIN) - 1).leading_zeros();
        bucket_bits as usize - const { BUCKET_MIN.trailing_zeros() as usize }
    }

    /// Allocate memory of at least the given size, which returns to the pool when dropped.
    fn alloc(&self, size: usize) -> Pages {
        self.buckets[Self::bucket_idx(size)].alloc()
    }

    /// Return the (not pooled) read-write `pages` to the pool.
    fn free(&self, pages: Pages) {
        self.buckets[Self::bucket_idx(pages.len)].free(pages)
    }
}

static ALLOCATOR: LazyLock<BucketedFreeList> = LazyLock::new(BucketedFreeList::new);

// FIXME: evaluate (re-)using a `Box<[u8]>` with a custom allocator (soon to be stabilized in
// 1.100.)
/// Pages of memory, which are unmapped (or returned to the `FreeList`) when dropped.
struct Pages {
    raw: NonNull<u8>,
    len: usize,
    /// Does this allocation return to [`ALLOCATOR`] when dropped?
    pooled: bool,
}

// SAFETY: Proof by authority: `Pages` is roughly equivalent to a `Box<[u8]>`, which is `Send +
// Sync`.
unsafe impl Send for Pages {}
unsafe impl Sync for Pages {}

impl Pages {
    /// Map `len` bytes of zeroed, read-write pages.
    fn new(len: usize) -> Result<Self, EbpfError> {
        let raw = allocate_pages(len)?;
        Ok(Self {
            raw: NonNull::new(raw).expect("mapped pages at a null address"),
            len,
            pooled: false,
        })
    }
}

impl Drop for Pages {
    fn drop(&mut self) {
        let raw = self.raw.as_ptr();
        if self.pooled {
            // SAFETY:
            //
            // Contract from `protect_pages`: These pages must an allocation that the caller owns.
            // Contract from `protect_pages`: While `permissions` apply, nothing may access these
            // pages in a way that `permissions` do not allow.
            //
            // Evidence: `Pages` encapsulates the mapping, and read-write allows any access.
            match unsafe { protect_pages(raw, self.len, PagePermissions::ReadWrite) } {
                Ok(()) => {
                    return ALLOCATOR.free(Pages {
                        raw: self.raw,
                        len: self.len,
                        pooled: false,
                    })
                }
                Err(error) => {
                    log::error!("unable to return pages to the pool: {error}");
                }
            }
        }
        // SAFETY:
        //
        // Contract from `free_pages`: `raw` and `size_in_bytes` must be a mapping that
        // [`allocate_pages`] created, which is not freed already.
        // Contract from `free_pages`: Nothing may access the allocation afterwards.
        //
        // Evidence: `Pages` encapsulates the mapping. Being inside `Drop` means the last use of
        // this type is over.
        if let Err(error) = unsafe { free_pages(raw, self.len) } {
            log::error!("unable to free pages: {error}");
        }
    }
}

/// Access permissions of [`Mapping`].
pub(crate) trait Access {
    const PERMISSIONS: PagePermissions;
}

/// Pages that can only be read.
pub(crate) enum Read {}
impl Access for Read {
    const PERMISSIONS: PagePermissions = PagePermissions::Read;
}

/// Pages that can be read and written.
pub(crate) enum ReadWrite {}
impl Access for ReadWrite {
    const PERMISSIONS: PagePermissions = PagePermissions::ReadWrite;
}

/// Pages that can be read and executed.
pub(crate) enum ReadExecute {}
impl Access for ReadExecute {
    const PERMISSIONS: PagePermissions = PagePermissions::ReadExecute;
}

/// Slices of data backed by mapped [`Pages`], with `A` describing valid ways to access the data.
///
/// This type is a smart reference counting pointer representing a portion of an underlying memory
/// allocation. A single mapping can be subdivided into mutually disjoint parts, each with their own
/// independent access permissions. The underlying alloction is released when every `Mapping` backed
/// by this storage is discarded.
///
/// Each `Mapping` guarantees that the alignment of data is at least a single page's worth. That
/// said, the alignment and size of a page can differ based on the target architecture.
pub(crate) struct Mapping<A = ReadWrite> {
    /// Releases the pages once all `Mapping`s are dropped.
    pages: Arc<Pages>,
    ptr: NonNull<u8>,
    len: usize,
    access: PhantomData<A>,
}

// SAFETY: Proof by authority: `Mapping` is roughly equivalent to a `Box<[u8]>`, which is `Send +
// Sync`.
unsafe impl<A> Send for Mapping<A> {}
unsafe impl<A> Sync for Mapping<A> {}

impl Mapping {
    /// Allocate at least `len` bytes of pages from the pool.
    ///
    /// The data in allocated pages is can be arbitrary.
    pub(crate) fn pooled(len: usize) -> Self {
        Self::whole(ALLOCATOR.alloc(len))
    }

    /// All of the read-write `pages`.
    fn whole(pages: Pages) -> Self {
        Self {
            ptr: pages.raw,
            len: pages.len,
            pages: Arc::new(pages),
            access: PhantomData,
        }
    }

    /// Split into parts of byte-addressed ranges in `ranges`.
    ///
    /// Each range must start at a page boundary; conversely endpoint does not share this
    /// requirement.
    ///
    /// Each range must be mutually disjoint with all the other ranges.
    ///
    /// The bytes not addressed by `ranges` are no longer accessible through the successfully split
    /// `Mapping`s.
    ///
    /// If the mapping cannot be split into parts (whatever the reason,) the original mapping is
    /// returned.
    pub(crate) fn split<const N: usize>(
        mut self,
        ranges: [Range<usize>; N],
    ) -> Result<[Self; N], Self> {
        let page_size = get_system_page_size();
        for range in &ranges {
            if !range.start.is_multiple_of(page_size) {
                return Err(self);
            }
        }
        let Ok(parts) = self.get_disjoint_mut(ranges.clone()) else {
            return Err(self);
        };
        let parts = parts.map(|part| NonNull::from(part).cast::<u8>());
        Ok(std::array::from_fn(|i| Self {
            pages: Arc::clone(&self.pages),
            ptr: parts[i],
            len: ranges[i].len(),
            access: PhantomData,
        }))
    }
}

impl<A> Mapping<A> {
    /// Set the permissions of the pages that hold the bytes of `self` to `B`.
    pub(crate) fn protect<B: Access>(self) -> Result<Mapping<B>, EbpfError> {
        if self.len != 0 {
            // SAFETY:
            //
            // Contract from `protect_pages`: These pages must be of an allocation that the caller
            // owns.
            // Contract from `protect_pages`: While `permissions` apply, nothing may access these
            // pages in a way that `permissions` do not allow.
            //
            // Evidence: `self` owns the pages that hold its bytes. No other part has bytes in
            // them, and `self` is consumed, so no references to them can remain. Afterwards, they
            // are only accessed through the mapping returned, whose type says these permissions,
            // until it is dropped. Dropping the last part makes all pages read-write before they
            // are reused.
            unsafe { protect_pages(self.ptr.as_ptr(), self.len, B::PERMISSIONS) }?;
        }
        Ok(Mapping {
            pages: self.pages,
            ptr: self.ptr,
            len: self.len,
            access: PhantomData,
        })
    }

    /// Shorten `self` to `len` bytes, if it is longer, which makes the rest inaccessible.
    pub(crate) fn truncate(&mut self, len: usize) {
        self.len = self.len.min(len);
    }

    /// The size of the whole mapping that `self` is a part of.
    pub(crate) fn mapped_len(&self) -> usize {
        self.pages.len
    }
}

macro_rules! impl_many {
    (impl $trait:path [$(for $ty:ty),*] $body:tt) => {
        $( impl $trait for $ty $body )*
    };
}

impl_many! {
impl std::ops::Deref [
    for Mapping<Read>,
    for Mapping<ReadWrite>,
    for Mapping<ReadExecute>
] {
    type Target = [u8];

    #[inline]
    fn deref(&self) -> &[u8] {
        // SAFETY:
        //
        // Contract from `slice::from_raw_parts`: `data` must be non-null, valid for reads for `len
        // * size_of::<T>()` many bytes, and it must be properly aligned. This means in particular:
        // The entire memory range of this slice must be contained within a single allocation!
        // Slices can never span across multiple allocations.
        //
        // Contract from `slice::from_raw_parts`: The total size `len * size_of::<T>()` of the
        // slice must be no larger than `isize::MAX`, and adding that size to `data` must not "wrap
        // around" the address space. See the safety documentation of `pointer::offset`.
        //
        // Evidence: `T` is `u8`, so the pointer is always aligned. The `len` bytes at `ptr` are
        // within the pages, which `pages` keeps mapped as long as `self` is live. Mapping is a
        // single object, which by definition must fit in an `isize` bytes.
        //
        // Contract from `slice::from_raw_parts`: The memory referenced by the returned slice must
        // not be mutated for the duration of lifetime `'a`, except inside an `UnsafeCell`.
        //
        // Evidence: Borrows `Mapping` for the duration of the slice borrow.
        //
        // Contract from `slice::from_raw_parts`: `data` must point to `len` consecutive properly
        // initialized values of type `T`.
        //
        // Evidence: u8 has no initialization invariants.
        unsafe { std::slice::from_raw_parts(self.ptr.as_ptr(), self.len) }
    }
}
}

impl std::ops::DerefMut for Mapping<ReadWrite> {
    #[inline]
    fn deref_mut(&mut self) -> &mut [u8] {
        // SAFETY: See `impl Deref for Self`.
        unsafe { std::slice::from_raw_parts_mut(self.ptr.as_ptr(), self.len) }
    }
}

#[cfg(not(target_os = "windows"))]
macro_rules! libc_error_guard {
    (succeeded?, mmap, $addr:expr, $($arg:expr),*) => {{
        *$addr = libc::mmap(*$addr, $($arg),*);
        *$addr != libc::MAP_FAILED
    }};
    (succeeded?, $function:ident, $($arg:expr),*) => {
        libc::$function($($arg),*) == 0
    };
    ($function:ident, $($arg:expr),* $(,)?) => {{
        const RETRY_COUNT: usize = 3;
        for i in 0..RETRY_COUNT {
            if libc_error_guard!(succeeded?, $function, $($arg),*) {
                break;
            } else if i.saturating_add(1) == RETRY_COUNT {
                let args = vec![$(format!("{:?}", $arg)),*];
                #[cfg(any(target_os = "freebsd", target_os = "ios", target_os = "macos"))]
                let errno = *libc::__error();
                #[cfg(any(target_os = "android", target_os = "netbsd", target_os = "openbsd"))]
                let errno = *libc::__errno();
                #[cfg(target_os = "linux")]
                let errno = *libc::__errno_location();
                return Err(EbpfError::LibcInvocationFailed(stringify!($function), args, errno));
            }
        }
    }};
}

#[cfg(target_os = "windows")]
macro_rules! winapi_error_guard {
    (succeeded?, VirtualAlloc, $addr:expr, $($arg:expr),*) => {{
        *$addr = VirtualAlloc(*$addr, $($arg),*);
        !(*$addr).is_null()
    }};
    (succeeded?, $function:ident, $($arg:expr),*) => {
        $function($($arg),*) != 0
    };
    ($function:ident, $($arg:expr),* $(,)?) => {{
        if !winapi_error_guard!(succeeded?, $function, $($arg),*) {
            let args = vec![$(format!("{:?}", $arg)),*];
            let errno = GetLastError();
            return Err(EbpfError::LibcInvocationFailed(stringify!($function), args, errno as i32));
        }
    }};
}

pub(crate) fn get_system_page_size() -> usize {
    #[cfg(not(target_os = "windows"))]
    unsafe {
        libc::sysconf(libc::_SC_PAGESIZE) as usize
    }
    #[cfg(target_os = "windows")]
    unsafe {
        let mut system_info: SYSTEM_INFO = std::mem::zeroed();
        GetSystemInfo(&mut system_info);
        system_info.dwPageSize as usize
    }
}

pub(crate) fn round_to_page_size(value: usize, page_size: usize) -> usize {
    value
        .saturating_add(page_size)
        .saturating_sub(1)
        .checked_div(page_size)
        .unwrap()
        .saturating_mul(page_size)
}

fn allocate_pages(size_in_bytes: usize) -> Result<*mut u8, EbpfError> {
    unsafe {
        let mut raw: *mut c_void = std::ptr::null_mut();
        // SAFETY: mmap has no soundness invariants for the flags used here.
        #[cfg(not(target_os = "windows"))]
        libc_error_guard!(
            mmap,
            &mut raw,
            size_in_bytes,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_ANONYMOUS | libc::MAP_PRIVATE,
            -1,
            0,
        );
        // SAFETY: VirtualAlloc has no soundness invariants for the flags used here.
        #[cfg(target_os = "windows")]
        winapi_error_guard!(
            VirtualAlloc,
            &mut raw,
            size_in_bytes,
            winnt::MEM_RESERVE | winnt::MEM_COMMIT,
            winnt::PAGE_READWRITE,
        );
        Ok(raw.cast::<u8>())
    }
}

/// Unmap the pages of an allocation.
///
/// # Safety
///
/// - `raw` and `size_in_bytes` must be a mapping that [`allocate_pages`] created, which is not
///   freed already.
/// - Nothing may access the allocation afterwards.
unsafe fn free_pages(raw: *mut u8, size_in_bytes: usize) -> Result<(), EbpfError> {
    #[cfg(not(target_os = "windows"))]
    libc_error_guard!(munmap, raw.cast::<c_void>(), size_in_bytes);
    #[cfg(target_os = "windows")]
    winapi_error_guard!(
        VirtualFree,
        raw.cast::<c_void>(),
        size_in_bytes,
        winnt::MEM_RELEASE, // winnt::MEM_DECOMMIT
    );
    Ok(())
}

#[derive(Copy, Clone)]
pub(crate) enum PagePermissions {
    Read,
    ReadWrite,
    ReadExecute,
}

/// Set the access `permissions` of the pages containing any part of the `size_in_bytes` bytes at
/// `raw`, which must be aligned to a page boundary.
///
/// # Safety
///
/// - Specified pages must be in a mapping that the caller owns.
/// - While `permissions` apply, nothing may access these pages in a way that `permissions` do not
///   allow.
unsafe fn protect_pages(
    raw: *mut u8,
    size_in_bytes: usize,
    permissions: PagePermissions,
) -> Result<(), EbpfError> {
    #[cfg(not(target_os = "windows"))]
    {
        let prot = match permissions {
            PagePermissions::Read => libc::PROT_READ,
            PagePermissions::ReadWrite => libc::PROT_READ | libc::PROT_WRITE,
            PagePermissions::ReadExecute => libc::PROT_READ | libc::PROT_EXEC,
        };
        libc_error_guard!(mprotect, raw.cast::<c_void>(), size_in_bytes, prot);
    }
    #[cfg(target_os = "windows")]
    {
        let mut old: minwindef::DWORD = 0;
        let ptr_old: *mut minwindef::DWORD = &mut old;
        let prot = match permissions {
            PagePermissions::Read => winnt::PAGE_READONLY,
            PagePermissions::ReadWrite => winnt::PAGE_READWRITE,
            PagePermissions::ReadExecute => winnt::PAGE_EXECUTE_READ,
        };
        winapi_error_guard!(
            VirtualProtect,
            raw.cast::<c_void>(),
            size_in_bytes,
            prot,
            ptr_old,
        );
    }
    Ok(())
}

#[derive(Clone, Copy)]
enum Advice {
    DontNeed,
}

unsafe fn madvise(raw: *mut u8, size_in_bytes: usize, advice: Advice) -> Result<(), EbpfError> {
    #[cfg(not(target_os = "windows"))]
    {
        let advice = match advice {
            Advice::DontNeed => libc::MADV_DONTNEED,
        };
        libc_error_guard!(madvise, raw.cast::<c_void>(), size_in_bytes, advice);
    }

    #[cfg(target_os = "windows")]
    {
        let mut ptr = raw.cast::<c_void>();
        let advice = match advice {
            Advice::DontNeed => winnt::MEM_RESET,
        };
        winapi_error_guard!(
            VirtualAlloc,
            &mut ptr,
            size_in_bytes,
            advice,
            winnt::PAGE_READWRITE,
        );
    }

    Ok(())
}

#[cfg(test)]
#[expect(clippy::single_range_in_vec_init)]
mod tests {
    use super::*;

    /// `len` bytes of zeroed pages, which are not pooled.
    fn new(len: usize) -> Mapping {
        Mapping::whole(Pages::new(len).unwrap())
    }

    #[test]
    fn mapping_is_zeroed() {
        let mapping = new(get_system_page_size());
        assert!(mapping.iter().all(|&byte| byte == 0));
    }

    #[test]
    fn split_and_protect() {
        let page_size = get_system_page_size();
        let mapping = new(4 * page_size);
        let start = mapping.as_ptr();
        let Ok([mut a, b, mut c, empty]) = mapping.split([
            0..4,
            page_size..2 * page_size + 1,
            3 * page_size..4 * page_size,
            4 * page_size..4 * page_size,
        ]) else {
            unreachable!()
        };
        assert_eq!(a.len(), 4);
        assert_eq!(b.len(), page_size + 1);
        assert_eq!(c.as_ptr(), start.wrapping_add(3 * page_size));
        assert!(empty.is_empty());
        a.copy_from_slice(&[1, 2, 3, 4]);
        let a = a.protect::<Read>().unwrap();
        let empty = empty.protect::<ReadExecute>().unwrap();
        c.fill(5);
        drop(b);
        assert_eq!(*a, [1, 2, 3, 4]);
        let Ok([c0, c1]) = c.split([0..0, 0..2]) else {
            unreachable!()
        };
        let c1 = c1.protect::<ReadExecute>().unwrap();
        let mut c1 = c1.protect::<ReadWrite>().unwrap();
        c1[1] = 6;
        assert_eq!(*c1, [5, 6]);
        assert_eq!(a.mapped_len(), 4 * page_size);
        c1.truncate(1);
        assert_eq!(*c1, [5]);
        drop((a, c0, empty));
    }

    #[test]
    fn split_within_page() {
        assert!(new(get_system_page_size()).split([1..2]).is_err());
    }

    #[test]
    fn split_sharing_page() {
        let page_size = get_system_page_size();
        let ranges = [0..page_size + 1, page_size..2 * page_size];
        assert!(new(2 * page_size).split(ranges).is_err());
    }

    #[test]
    fn split_out_of_bounds() {
        let page_size = get_system_page_size();
        assert!(new(page_size).split([0..page_size + 1]).is_err());
    }

    #[test]
    fn split_reversed() {
        let page_size = get_system_page_size();
        assert!(new(2 * page_size).split([page_size..1]).is_err());
    }

    /// Pooled pages come back read-write from the pool, whatever they were made before.
    #[test]
    fn pooled_mapping_returns_writable() {
        for _ in 0..4 {
            let mut mapping = Mapping::pooled(BUCKET_MIN);
            assert_eq!(mapping.len(), BUCKET_MIN);
            mapping.fill(0xcc);
            let Ok([head, tail]) = mapping.split([0..1, BUCKET_MIN / 2..BUCKET_MIN]) else {
                unreachable!()
            };
            let head = head.protect::<Read>().unwrap();
            let tail = tail.protect::<ReadExecute>().unwrap();
            assert_eq!(tail[BUCKET_MIN / 2 - 1], 0xcc);
            drop(tail);
            assert_eq!(*head, [0xcc]);
        }
    }
}

// Copyright 2022 Solana Maintainers <maintainers@solana.com>
//
// Licensed under the Apache License, Version 2.0 <http://www.apache.org/licenses/LICENSE-2.0> or
// the MIT license <http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

#[cfg(feature = "shuttle-test")]
use shuttle::rand;

use crate::error::EbpfError;
use rand::{thread_rng, Rng};
use std::ffi::c_void;
use std::fs::File;
use std::marker::PhantomData;
use std::ops::Range;
use std::ptr::NonNull;
use std::sync::{Arc, LazyLock, Mutex};

#[cfg(target_os = "windows")]
use windows_sys::Win32::{
    Foundation::{CloseHandle, GetLastError, ERROR_NOT_ENOUGH_MEMORY},
    System::{
        Memory::{
            CreateFileMappingW, MapViewOfFileEx, UnmapViewOfFile, VirtualAlloc, VirtualFree,
            VirtualProtect, FILE_MAP_COPY, FILE_MAP_EXECUTE, MEMORY_MAPPED_VIEW_ADDRESS,
            MEM_COMMIT, MEM_RELEASE, MEM_RESERVE, MEM_RESET, PAGE_EXECUTE_READ,
            PAGE_EXECUTE_WRITECOPY, PAGE_PROTECTION_FLAGS, PAGE_READONLY, PAGE_READWRITE,
        },
        SystemInformation::{GetSystemInfo, SYSTEM_INFO},
    },
};

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
        'result: {
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
                    break 'result Err(EbpfError::LibcInvocationFailed(stringify!($function), args, errno));
                }
            }
            Ok(())
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
            Err(EbpfError::LibcInvocationFailed(stringify!($function), args, errno as i32))
        } else {
            Ok(())
        }
    }};
}

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
        let mut pages = pages.unwrap_or_else(|| {
            Mapping::builder(self.size)
                .map_pages()
                .expect("allocation failed")
        });
        pages.origin = Origin::Pooled;
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
            let raw = pages.raw.as_ptr().cast::<c_void>();
            // SAFETY: discarding the contents of the pages has no soundness invariants: they are
            // read-write, and nothing refers to them while they are in the pool.
            let result = unsafe {
                cfg_select! {
                    windows => {
                        let mut raw = raw;
                        winapi_error_guard!(VirtualAlloc, &mut raw, pages.len, MEM_RESET, PAGE_READWRITE)
                    }
                    _ => {
                        libc_error_guard!(madvise, raw, pages.len, libc::MADV_DONTNEED)
                    }
                }
            };
            if let Err(e) = result {
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
/// Mapped pages of memory.
struct Pages {
    raw: NonNull<u8>,
    len: usize,
    origin: Origin,
}

/// How [`Pages`] were materialized.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Origin {
    /// Anonymous memory.
    Anonymous,
    /// Memory from the pool [`ALLOCATOR`].
    Pooled,
    /// A view of a file.
    File,
}

// SAFETY: Proof by authority: `Pages` is roughly equivalent to a `Box<[u8]>`, which is `Send +
// Sync`.
unsafe impl Send for Pages {}
unsafe impl Sync for Pages {}

impl Drop for Pages {
    fn drop(&mut self) {
        let raw = self.raw.as_ptr();
        if self.origin == Origin::Pooled {
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
                        origin: Origin::Anonymous,
                    })
                }
                Err(error) => {
                    log::error!("unable to return pages to the pool: {error}");
                }
            }
        }
        let unmap_result = unsafe {
            // SAFETY:
            //
            // Contract: `munmap` should only free pages that we hold ownership over.
            //
            // Evidence: `Pages` encapsulates the mapping. Being inside `Drop` means the last use of
            // this type is over.
            cfg_select! {
                windows => {
                    if self.origin == Origin::File {
                        let view = MEMORY_MAPPED_VIEW_ADDRESS { Value: raw.cast::<c_void>() };
                        if UnmapViewOfFile(view) == 0 {
                            let errno = GetLastError() as i32;
                            let args = vec![format!("{raw:?}")];
                            Err(EbpfError::LibcInvocationFailed("UnmapViewOfFile", args, errno))
                        } else {
                            Ok(())
                        }
                    } else {
                        winapi_error_guard!(VirtualFree, raw.cast::<c_void>(), 0, MEM_RELEASE)
                    }
                }
                _ => {
                    libc_error_guard!(munmap, raw.cast::<c_void>(), self.len)
                }
            }
        };
        if let Err(error) = unmap_result {
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

    /// A builder of a mapping of `len` bytes of new, read-write pages.
    pub(crate) fn builder(len: usize) -> MappingBuilder<'static> {
        MappingBuilder {
            len,
            low: false,
            file: None,
        }
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

/// How to map new pages, see [`Mapping::builder`]. They hold zeroes, unless they are of a file.
pub(crate) struct MappingBuilder<'a> {
    len: usize,
    /// Within the first 2 GiB of the address space.
    low: bool,
    /// The file, and the offset in it, to map the pages of.
    file: Option<(&'a File, u64)>,
}

impl<'a> MappingBuilder<'a> {
    /// Place the pages within the first 2 GiB of the address space, at a random address, so that
    /// code in them can be addressed with sign-extended 32-bit absolute addresses.
    ///
    /// The pages are mapped in a retry loop, so this is not for performance-sensitive code.
    #[cfg_attr(not(all(test, target_arch = "x86_64")), expect(dead_code))]
    pub(crate) fn low(self) -> Self {
        Self { low: true, ..self }
    }

    /// Map the pages of `file` from `offset` on. The offset must be a multiple of the page size,
    /// and on Windows of the allocation granularity, which is 64 KiB. The file must be open for
    /// reading, and on Windows for execution too.
    ///
    /// The mapping is private: the pages are copied when they are first written to, so what is
    /// written through the mapping does not reach the file. Debuggers can insert breakpoints into
    /// private mappings that are executable, but not into shared ones.
    ///
    /// # Safety
    ///
    /// Until the mapping is dropped, the file must not be shortened below `offset` plus the length
    /// of the mapping, and the bytes there may only be overwritten with those that the mapping has
    /// at the same position, as pages that were not written to yet show what the file holds.
    #[cfg_attr(not(all(test, not(target_os = "windows"))), expect(dead_code))]
    pub(crate) unsafe fn file<'b>(self, file: &'b File, offset: u64) -> MappingBuilder<'b> {
        MappingBuilder {
            len: self.len,
            low: self.low,
            file: Some((file, offset)),
        }
    }

    /// The length of the mapping.
    #[cfg_attr(not(all(test, not(target_os = "windows"))), expect(dead_code))]
    pub(crate) fn len(&self) -> usize {
        self.len
    }

    /// Map the pages.
    #[cfg_attr(not(test), expect(dead_code))]
    pub(crate) fn build(self) -> Result<Mapping, EbpfError> {
        Ok(Mapping::whole(self.map_pages()?))
    }

    fn map_pages(self) -> Result<Pages, EbpfError> {
        if !self.low {
            return self.map_at(std::ptr::null_mut());
        }
        /// Same as the allocation granularity of Windows.
        const ALIGNMENT: usize = 64 * 1024;
        const LOWEST: usize = 256 * 1024 * 1024;
        const HIGHEST: usize = 2 * 1024 * 1024 * 1024;
        const ATTEMPTS: usize = 64;

        let slots = HIGHEST
            .saturating_sub(LOWEST)
            .checked_sub(self.len)
            .map(|spare| spare.saturating_div(ALIGNMENT).saturating_add(1));
        let mut error = None;
        for _ in 0..slots.map_or(0, |_| ATTEMPTS) {
            let slot = thread_rng().gen_range(0..slots.unwrap_or(1));
            let hint = LOWEST.saturating_add(slot.saturating_mul(ALIGNMENT)) as *mut c_void;
            match self.map_at(hint) {
                Ok(pages) if pages.raw.as_ptr() == hint.cast() => return Ok(pages),
                // Without `MAP_FIXED` the address hint is only honored if the range is free and the
                // allocated pages might be elsewhere.
                Ok(_) => continue,
                // `VirtualAlloc` and `MapViewOfFileEx` fail if the range is occupied.
                Err(e) => error = Some(e),
            }
        }
        Err(error.unwrap_or_else(|| {
            let (function, errno) = cfg_select! {
                windows => ("VirtualAlloc", ERROR_NOT_ENOUGH_MEMORY as i32),
                _ => ("mmap", libc::ENOMEM)
            };
            EbpfError::LibcInvocationFailed(function, vec![format!("{:?}", self.len)], errno)
        }))
    }

    /// Map the pages, at `hint` if it is not null and the system places them there.
    fn map_at(&self, hint: *mut c_void) -> Result<Pages, EbpfError> {
        let len = self.len;
        // SAFETY: mapping new pages has no soundness invariants for the flags used here, as
        // nothing refers to them yet. For the pages of a file, see `file`.
        let raw = unsafe {
            cfg_select! {
                windows => match self.file {
                    None => {
                        let mut raw = hint;
                        winapi_error_guard!(
                            VirtualAlloc,
                            &mut raw,
                            len,
                            MEM_RESERVE | MEM_COMMIT,
                            PAGE_READWRITE,
                        )?;
                        raw
                    }
                    // Copy-on-write views start out read-write, and can be made read-only or
                    // executable.
                    Some((file, offset)) => {
                        let failed = |function, errno: u32| {
                            let args = vec![format!("{len:?}"), format!("{offset:?}")];
                            EbpfError::LibcInvocationFailed(function, args, errno as i32)
                        };
                        let handle = std::os::windows::io::AsRawHandle::as_raw_handle(file);
                        let section = CreateFileMappingW(
                            handle,
                            std::ptr::null(),
                            PAGE_EXECUTE_WRITECOPY,
                            0,
                            0,
                            std::ptr::null(),
                        );
                        if section.is_null() {
                            return Err(failed("CreateFileMappingW", GetLastError()));
                        }
                        let view = MapViewOfFileEx(
                            section,
                            FILE_MAP_COPY | FILE_MAP_EXECUTE,
                            (offset >> 32) as u32,
                            offset as u32,
                            len,
                            hint,
                        );
                        let errno = GetLastError();
                        // The view keeps the section alive.
                        CloseHandle(section);
                        if view.Value.is_null() {
                            return Err(failed("MapViewOfFileEx", errno));
                        }
                        view.Value
                    }
                },
                _ => {
                    let (flags, fd, offset) = match self.file {
                        None => {
                            cfg_select! {
                                target_os = "linux" => (libc::MAP_ANONYMOUS | libc::MAP_SHARED, -1, 0),
                                _ => (libc::MAP_ANONYMOUS | libc::MAP_PRIVATE, -1, 0),
                            }
                        }
                        Some((file, offset)) => (
                            libc::MAP_PRIVATE,
                            std::os::fd::AsRawFd::as_raw_fd(file),
                            <libc::off_t as std::convert::TryFrom<u64>>::try_from(offset)
                                .expect("file offset out of range"),
                        ),
                    };
                    let mut raw = hint;
                    libc_error_guard!(
                        mmap,
                        &mut raw,
                        len,
                        libc::PROT_READ | libc::PROT_WRITE,
                        flags,
                        fd,
                        offset,
                    )?;
                    #[cfg(target_os = "linux")]
                    if self.file.is_none() {
                        libc_error_guard!(madvise, raw, len, libc::MADV_DONTFORK)?;
                    }
                    raw
                }
            }
        };
        Ok(Pages {
            raw: NonNull::new(raw.cast::<u8>()).expect("mapped pages at a null address"),
            len,
            origin: match self.file {
                None => Origin::Anonymous,
                Some(_) => Origin::File,
            },
        })
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
    cfg_select! {
        windows => {
            let mut old: PAGE_PROTECTION_FLAGS = 0;
            let ptr_old: *mut PAGE_PROTECTION_FLAGS = &mut old;
            let prot = match permissions {
                PagePermissions::Read => PAGE_READONLY,
                PagePermissions::ReadWrite => PAGE_READWRITE,
                PagePermissions::ReadExecute => PAGE_EXECUTE_READ,
            };
            winapi_error_guard!(VirtualProtect, raw.cast::<c_void>(), size_in_bytes, prot, ptr_old)
        }
        _ => {
            let prot = match permissions {
                PagePermissions::Read => libc::PROT_READ,
                PagePermissions::ReadWrite => libc::PROT_READ | libc::PROT_WRITE,
                PagePermissions::ReadExecute => libc::PROT_READ | libc::PROT_EXEC,
            };
            libc_error_guard!(mprotect, raw.cast::<c_void>(), size_in_bytes, prot)
        }
    }
}

#[cfg(test)]
#[expect(clippy::single_range_in_vec_init)]
mod tests {
    use super::*;

    /// `len` bytes of zeroed pages, which are not pooled.
    fn new(len: usize) -> Mapping {
        Mapping::builder(len).build().unwrap()
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

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn low_mapping() {
        let len = 2 * get_system_page_size();
        let mut mapping = Mapping::builder(len).low().build().unwrap();
        let end = mapping.as_ptr_range().end as usize;
        assert!(end <= 1 << 31, "{:#x}", end);
        assert!(mapping.iter().all(|&byte| byte == 0));
        mapping.fill(0xcc);
        let mapping = mapping.protect::<ReadExecute>().unwrap();
        assert!(mapping.iter().all(|&byte| byte == 0xcc));
    }

    /// A file mapping shows the contents of the file, and writes to it do not reach the file.
    #[cfg(not(target_os = "windows"))]
    #[test]
    fn file_mapping() {
        use std::io::{Read as _, Seek as _, Write as _};
        let page_size = get_system_page_size();
        let path = std::env::temp_dir().join(format!("sbpf-file-mapping-{}", std::process::id()));
        let mut file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(&path)
            .unwrap();
        std::fs::remove_file(&path).unwrap();
        let contents: Vec<u8> = (0..3 * page_size)
            .map(|i| (i / page_size) as u8 + 1)
            .collect();
        file.write_all(&contents).unwrap();
        // SAFETY: the file is not changed while it is mapped.
        let builder = unsafe { Mapping::builder(2 * page_size).file(&file, page_size as u64) };
        assert_eq!(builder.len(), 2 * page_size);
        let mut mapping = builder.build().unwrap();
        assert_eq!(&mapping[..], &contents[page_size..]);
        mapping.fill(0xcc);
        let mapping = mapping.protect::<ReadExecute>().unwrap();
        assert!(mapping.iter().all(|&byte| byte == 0xcc));
        drop(mapping);
        let mut read = Vec::new();
        file.rewind().unwrap();
        file.read_to_end(&mut read).unwrap();
        assert_eq!(read, contents);
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

// Copyright 2022 Solana Maintainers <maintainers@solana.com>
//
// Licensed under the Apache License, Version 2.0 <http://www.apache.org/licenses/LICENSE-2.0> or
// the MIT license <http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

#![cfg_attr(target_os = "windows", allow(dead_code))]

use std::sync::{LazyLock, Mutex};

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
    mem: Mutex<Vec<*mut u8>>,
    /// The size of each memory block.
    size: usize,
}

// Safety: FreeList only stores mmap allocation base addresses. The pointed-to
// memory is not accessed through FreeList without holding the FreeList
// mutex, and ownership of each allocation is transferred into/out of the pool.
unsafe impl Sync for FreeList {}
unsafe impl Send for FreeList {}

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
    /// If a free block is available, it is reused; otherwise, a new block is allocated.
    ///
    /// Returns a pointer to the allocated memory and the size of the allocation.
    /// Returned memory has read-write permissions and may contain arbitrary
    /// bytes left over from a previous owner; the caller should not assume
    /// any particular contents.
    fn alloc(&self) -> (*mut u8, usize) {
        let ptr = { self.mem.lock().unwrap_or_else(|e| e.into_inner()).pop() };
        let ptr = match ptr {
            Some(ptr) => ptr,
            None => unsafe { allocate_pages(self.size) }.expect("allocation failed"),
        };

        (ptr, self.size)
    }

    /// Free the given allocation, returning it to the pool.
    ///
    /// # Safety
    ///
    /// - `ptr` must have been returned by [`FreeList::alloc`] on this same
    ///   instance and not already returned to the pool.
    /// - `size` must equal the size configured at construction.
    /// - The caller must not retain any reference into the block after calling
    ///   `free`; subsequent `alloc` calls may hand the same memory to another
    ///   owner.
    unsafe fn free(&self, ptr: *mut u8, size: usize) {
        /// The threshold for discarding physical backing from returned memory.
        ///
        /// Allocations at or above 128 MiB are uncommon, so drop their
        /// resident pages when they are returned to the pool.
        const MADV_DONTNEED_THRESHOLD: usize = 1024 * 1024 * 128; // 128 MiB

        if size != self.size {
            panic!("free size mismatch: expected {}, got {}", self.size, size);
        }

        unsafe { protect_pages(ptr, self.size, PagePermissions::ReadWrite) }
            .expect("failed to protect pages");

        if self.size >= MADV_DONTNEED_THRESHOLD {
            if let Err(e) = unsafe { madvise(ptr, self.size, Advice::DontNeed) } {
                log::error!("FreeList: unable to advise returned allocation: {e}");
            }
        }

        self.mem.lock().unwrap_or_else(|e| e.into_inner()).push(ptr);
    }
}

impl Drop for FreeList {
    fn drop(&mut self) {
        for ptr in self
            .mem
            .get_mut()
            .unwrap_or_else(|e| e.into_inner())
            .drain(..)
        {
            if let Err(e) = unsafe { free_pages(ptr, self.size) } {
                log::error!("FreeList: unable to free {e}");
            }
        }
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
    ///
    /// Errors if the allocation would exceed the maximum bucket size, [`BUCKET_MAX`].
    #[inline]
    fn bucket_idx(&self, size: usize) -> usize {
        let bucket_size = size
            .max(BUCKET_MIN)
            .checked_next_power_of_two()
            .expect("allocation would exceed usize::MAX");
        (bucket_size / BUCKET_MIN).trailing_zeros() as usize
    }

    /// Allocate memory of at least the given size, returning a pointer to the allocation
    /// and the actual size allocated.
    fn alloc(&self, size: usize) -> (*mut u8, usize) {
        self.buckets[self.bucket_idx(size)].alloc()
    }

    /// Free the given allocation, returning it to the pool.
    ///
    /// # Safety
    ///
    /// - `ptr` must have been returned by [`BucketedFreeList::alloc`] on this same
    ///   instance and not already returned to the pool.
    /// - The caller must not retain any reference into the block after calling
    ///   `free`; subsequent `alloc` calls may hand the same memory to another
    ///   owner.
    unsafe fn free(&self, ptr: *mut u8, size: usize) {
        unsafe { self.buckets[self.bucket_idx(size)].free(ptr, size) }
    }
}

static ALLOCATOR: LazyLock<BucketedFreeList> = LazyLock::new(BucketedFreeList::new);

/// Allocate memory of at least the given size, returning a pointer to the allocation
/// and the actual size allocated.
pub fn allocate_pages_pooled(size: usize) -> (*mut u8, usize) {
    ALLOCATOR.alloc(size)
}

/// Free the given allocation.
///
/// # Safety
///
/// - The pointer and size must identify a full allocation previously returned by
///   [`allocate_pages_pooled`] and not already returned to the pool.
/// - The caller must not retain any reference into the allocation after calling
///   `free`; subsequent `alloc` calls may hand the same memory to another
///   owner.
pub unsafe fn free_pages_pooled(ptr: *mut u8, size: usize) {
    unsafe { ALLOCATOR.free(ptr, size) }
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

pub fn get_system_page_size() -> usize {
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

pub fn round_to_page_size(value: usize, page_size: usize) -> usize {
    value
        .saturating_add(page_size)
        .saturating_sub(1)
        .checked_div(page_size)
        .unwrap()
        .saturating_mul(page_size)
}

pub unsafe fn allocate_pages(size_in_bytes: usize) -> Result<*mut u8, EbpfError> {
    let mut raw: *mut c_void = std::ptr::null_mut();
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

pub unsafe fn free_pages(raw: *mut u8, size_in_bytes: usize) -> Result<(), EbpfError> {
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
pub enum PagePermissions {
    Read,
    ReadWrite,
    ReadExecute,
}

pub unsafe fn protect_pages(
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
pub enum Advice {
    DontNeed,
}

pub unsafe fn madvise(raw: *mut u8, size_in_bytes: usize, advice: Advice) -> Result<(), EbpfError> {
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

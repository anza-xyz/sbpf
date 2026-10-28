// 4096 functions, each calling a syscall with the address of a table of all of them, so that
// for SBPFv0 loading has every kind of relocation to process: a syscall relocation and an
// address relocation per function, and a relative relocation per table entry.

#[cfg(target_feature = "static-syscalls")]
mod syscalls;
#[cfg(not(target_feature = "static-syscalls"))]
mod syscalls {
    extern "C" {
        pub fn log_64(arg1: u64, arg2: u64, arg3: u64, arg4: u64, arg5: u64);
    }
}

type Function = fn(u64) -> u64;

#[inline(never)]
fn function<const N: u64>(x: u64) -> u64 {
    unsafe { syscalls::log_64(x, N, TABLE.as_ptr() as u64, 0, 0) };
    x.wrapping_mul(N | 1).rotate_left((N % 63) as u32 + 1) ^ N
}

// Each level doubles the entries, appending a bit to the function's index.
macro_rules! table {
    (0, $n:expr) => { function::<{ $n }> as Function };
    (12, $n:expr) => { [table!(11, $n * 2), table!(11, $n * 2 + 1)] };
    (11, $n:expr) => { [table!(10, $n * 2), table!(10, $n * 2 + 1)] };
    (10, $n:expr) => { [table!(9, $n * 2), table!(9, $n * 2 + 1)] };
    (9, $n:expr) => { [table!(8, $n * 2), table!(8, $n * 2 + 1)] };
    (8, $n:expr) => { [table!(7, $n * 2), table!(7, $n * 2 + 1)] };
    (7, $n:expr) => { [table!(6, $n * 2), table!(6, $n * 2 + 1)] };
    (6, $n:expr) => { [table!(5, $n * 2), table!(5, $n * 2 + 1)] };
    (5, $n:expr) => { [table!(4, $n * 2), table!(4, $n * 2 + 1)] };
    (4, $n:expr) => { [table!(3, $n * 2), table!(3, $n * 2 + 1)] };
    (3, $n:expr) => { [table!(2, $n * 2), table!(2, $n * 2 + 1)] };
    (2, $n:expr) => { [table!(1, $n * 2), table!(1, $n * 2 + 1)] };
    (1, $n:expr) => { [table!(0, $n * 2), table!(0, $n * 2 + 1)] };
}

// The nested arrays of `table!` have the layout of a flat one.
const ENTRIES: [Function; 4096] = unsafe { core::mem::transmute(table!(12, 0)) };

// Exported for SBPFv0, so that its address is relocated rather than resolved by the linker.
#[cfg(not(target_feature = "static-syscalls"))]
#[no_mangle]
pub static TABLE: [Function; 4096] = ENTRIES;
#[cfg(target_feature = "static-syscalls")]
static TABLE: [Function; 4096] = ENTRIES;

#[no_mangle]
pub fn entrypoint(x: &u64) -> u64 {
    TABLE[*x as usize % TABLE.len()](*x)
}

// 4096 distinct functions, each called once from the entrypoint, so that loading has as many
// call targets to register and, for SBPFv0, as many call sites to relocate.

#[inline(never)]
fn function<const N: u64>(x: u64) -> u64 {
    x.wrapping_mul(N | 1).rotate_left((N % 63) as u32 + 1) ^ N
}

// Each level doubles the calls, appending a bit to the function's index.
macro_rules! calls {
    (0, $x:ident, $n:expr) => { $x = function::<{ $n }>($x); };
    (12, $x:ident, $n:expr) => { calls!(11, $x, $n * 2); calls!(11, $x, $n * 2 + 1); };
    (11, $x:ident, $n:expr) => { calls!(10, $x, $n * 2); calls!(10, $x, $n * 2 + 1); };
    (10, $x:ident, $n:expr) => { calls!(9, $x, $n * 2); calls!(9, $x, $n * 2 + 1); };
    (9, $x:ident, $n:expr) => { calls!(8, $x, $n * 2); calls!(8, $x, $n * 2 + 1); };
    (8, $x:ident, $n:expr) => { calls!(7, $x, $n * 2); calls!(7, $x, $n * 2 + 1); };
    (7, $x:ident, $n:expr) => { calls!(6, $x, $n * 2); calls!(6, $x, $n * 2 + 1); };
    (6, $x:ident, $n:expr) => { calls!(5, $x, $n * 2); calls!(5, $x, $n * 2 + 1); };
    (5, $x:ident, $n:expr) => { calls!(4, $x, $n * 2); calls!(4, $x, $n * 2 + 1); };
    (4, $x:ident, $n:expr) => { calls!(3, $x, $n * 2); calls!(3, $x, $n * 2 + 1); };
    (3, $x:ident, $n:expr) => { calls!(2, $x, $n * 2); calls!(2, $x, $n * 2 + 1); };
    (2, $x:ident, $n:expr) => { calls!(1, $x, $n * 2); calls!(1, $x, $n * 2 + 1); };
    (1, $x:ident, $n:expr) => { calls!(0, $x, $n * 2); calls!(0, $x, $n * 2 + 1); };
}

#[no_mangle]
pub fn entrypoint(x: &u64) -> u64 {
    let mut x = *x;
    calls!(12, x, 0);
    x
}

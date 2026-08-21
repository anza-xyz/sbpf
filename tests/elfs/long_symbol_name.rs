// Two symbols the label paths have to handle: one mangles to more than
// SYMBOL_NAME_LENGTH_MAXIMUM but less than DEBUG_SYMBOL_NAME_LENGTH_MAXIMUM, the
// other to more than both. The first is called through a pointer so that the
// relative call registration does not claim its slot first.
static VAL: u64 = 1;

#[inline(never)]
fn a_function_whose_mangled_name_is_over_the_relocation_limit_but_under_the_debug_limit(
    x: u64,
) -> u64 {
    x.wrapping_add(unsafe { core::ptr::read_volatile(&VAL) })
}

#[inline(never)]
fn a_function_whose_mangled_name_is_over_the_debug_limit_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa(
    x: u64,
) -> u64 {
    x.wrapping_mul(unsafe { core::ptr::read_volatile(&VAL) })
}

static FUNC: fn(u64) -> u64 =
    a_function_whose_mangled_name_is_over_the_relocation_limit_but_under_the_debug_limit;

#[no_mangle]
pub fn entrypoint(input: *mut u8) -> u64 {
    unsafe {
        let f = core::ptr::read_volatile(&FUNC);
        *input = a_function_whose_mangled_name_is_over_the_debug_limit_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa(f(*input as u64)) as u8;
    }
    0
}

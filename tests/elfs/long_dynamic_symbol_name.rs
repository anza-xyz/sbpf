// An undefined symbol longer than SYMBOL_NAME_LENGTH_MAXIMUM, resolved through
// the dynamic symbol table during relocation.
extern "C" {
    fn a_syscall_whose_name_is_longer_than_the_relocation_symbol_name_limit_which_is_64_bytes(x: u64) -> u64;
}

#[no_mangle]
pub fn entrypoint(input: *mut u8) -> u64 {
    unsafe {
        *input = a_syscall_whose_name_is_longer_than_the_relocation_symbol_name_limit_which_is_64_bytes(*input as u64) as u8;
    }
    0
}

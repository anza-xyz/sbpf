// 256 KiB of read-only data, read by an index, so that loading has a large read-only section to
// copy and little else.

const LEN: usize = 256 * 1024;

static DATA: [u8; LEN] = data();

// xorshift64 output, so that the data cannot be compressed into `.bss` or a smaller section.
const fn data() -> [u8; LEN] {
    let mut data = [0; LEN];
    let mut state: u64 = 0x9e37_79b9_7f4a_7c15;
    let mut i = 0;
    while i < LEN {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        data[i] = state as u8;
        i += 1;
    }
    data
}

#[no_mangle]
pub fn entrypoint(index: &u64) -> u64 {
    DATA[*index as usize % LEN] as u64
}

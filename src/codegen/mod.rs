pub mod x64;

const MAX_RELOCATIONS: usize = 16;

#[derive(Copy, Clone)]
struct Template<const SIZE: usize, R: Copy> {
    buffer: [u8; SIZE],
    bytes: usize,
    // Relocations based on BPF instruction contents (offset, immediate) for which this template is
    // instantiated for.
    relocations: [std::mem::MaybeUninit<R>; MAX_RELOCATIONS],
    num_relocations: usize,
}

impl<const SIZE: usize, R: Copy> Template<SIZE, R> {
    pub const fn new() -> Self {
        Self {
            buffer: [0; SIZE],
            bytes: 0,
            relocations: [std::mem::MaybeUninit::uninit(); MAX_RELOCATIONS],
            num_relocations: 0,
        }
    }

    pub const fn buffer(&self) -> &[u8] {
        unsafe { std::slice::from_raw_parts(self.buffer.as_ptr(), self.bytes) }
    }

    pub const fn buffer_mut(&mut self) -> &mut [u8] {
        unsafe { std::slice::from_raw_parts_mut(self.buffer.as_mut_ptr(), self.bytes) }
    }

    pub const fn relocations(&self) -> &[R] {
        unsafe {
            std::slice::from_raw_parts(self.relocations.as_ptr().cast::<R>(), self.num_relocations)
        }
    }

    pub const fn add_relocation(&mut self, relocation: R) {
        self.relocations[self.num_relocations].write(relocation);
        self.num_relocations += 1;
    }

    #[track_caller]
    pub const fn extend(&mut self, buffer: &[u8]) {
        let mut i = 0;
        while i < buffer.len() {
            self.buffer[self.bytes] = buffer[i];
            self.bytes += 1;
            i += 1;
        }
    }

    pub const fn offset(&self) -> usize {
        self.bytes
    }

    pub const fn push(&mut self, byte: u8) {
        self.buffer[self.bytes] = byte;
        self.bytes += 1;
    }

    pub const fn align(&mut self, alignment: usize, with: u8) {
        let mut to_add = (alignment - self.bytes % alignment) % alignment;
        while to_add != 0 {
            self.buffer[self.bytes] = with;
            self.bytes += 1;
            to_add -= 1;
        }
    }

    pub const fn push_i8(&mut self, value: i8) {
        self.push(value as u8);
    }

    pub const fn push_i16(&mut self, value: i16) {
        self.extend(&i16::to_le_bytes(value));
    }

    pub const fn push_i32(&mut self, value: i32) {
        self.extend(&i32::to_le_bytes(value));
    }

    pub const fn push_i64(&mut self, value: i64) {
        self.extend(&i64::to_le_bytes(value));
    }

    pub const fn push_u16(&mut self, value: u16) {
        self.extend(&u16::to_le_bytes(value));
    }

    pub const fn push_u32(&mut self, value: u32) {
        self.extend(&u32::to_le_bytes(value));
    }

    pub const fn push_u64(&mut self, value: u64) {
        self.extend(&u64::to_le_bytes(value));
    }

    pub const fn runtime_error(&self, msg: &'static str) {
        panic!("{}", msg);
    }

    pub const fn local_label(&mut self, _name: &'static str) {}
    pub const fn forward_reloc(
        &mut self,
        _name: &'static str,
        _target_offset: isize,
        _field_offset: u8,
        _ref_offset: u8,
        _kind: u8,
    ) {
    }
    pub const fn backward_reloc(
        &mut self,
        _name: &'static str,
        _target_offset: isize,
        _field_offset: u8,
        _ref_offset: u8,
        _kind: u8,
    ) {
    }
}

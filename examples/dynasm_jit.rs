const BUDGET: u64 = 10_000_000;

fn main() {
    let bpf = Vec::from([
        191, 33, 0, 0, 0, 0, 0, 0,
        87, 1, 0, 0, 255, 3, 0, 0,
        7, 2, 0, 0, 1, 0, 0, 0,
        165, 2, 252, 255, 0x00, 0x00, 0x20, 0x00,
        149, 0, 0, 0, 0, 0, 0, 0,
    ]);

    let code = solana_sbpf::codegen::x64::jit(&bpf);
    for b in &code {
        print!("{:02X}", b);
    }
    println!();

    let mut buffer = dynasmrt::mmap::MutableBuffer::new(code.len()).unwrap();
    buffer.set_len(code.len());
    buffer.copy_from_slice(&code);
    let buffer = buffer.make_exec().unwrap();
    let entrypoint = buffer.as_ptr() as usize;

    let mut duration = std::time::Duration::new(0, 0);
    let iters = 500;
    let mut remaining = 0;
    for _ in 0..iters {
        let start = std::time::Instant::now();
        let mut meter = BUDGET;
        let mut registers = [0u64; 11];
        let vm_ptr = registers.as_mut_ptr().cast::<u8>();
        let ret = std::hint::black_box(solana_sbpf::codegen::x64::enter(&bpf, entrypoint, &mut meter, vm_ptr, 0));
        remaining = meter;
        duration += start.elapsed();
        assert_eq!(ret, 0);
    }
    println!("{:?}, remaining budget: {remaining}", duration / iters);

    // let mut duration = std::time::Duration::new(0, 0);
    // let iters = 500;
    // for i in 0..iters {
    //         let start = std::time::Instant::now();
    //         std::hint::black_box(solana_sbpf::codegen::x64::interpret(&bpf));
    //         duration += start.elapsed();
    // }
    // println!("{:?}", duration / iters);
}

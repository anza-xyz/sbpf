const BUDGET: u64 = 10_000_000;

fn main() {
    let bpf = [
        191, 33, 0, 0, 0, 0, 0, 0,
        87, 1, 0, 0, 255, 3, 0, 0,
        7, 2, 0, 0, 1, 0, 0, 0,
        165, 2, 252, 255, 0x00, 0x00, 0x20, 0x00,
        149, 0, 0, 0, 0, 0, 0, 0,
    ];
    let mut duration = std::time::Duration::new(0, 0);
    let iters = 500;
    let mut remaining = 0;
    for i in 0..iters {
            let start = std::time::Instant::now();
            let mut meter = BUDGET;
            let mut registers = [0u64; 11];
            let vm_ptr = registers.as_mut_ptr().cast::<u8>();
            std::hint::black_box(solana_sbpf::codegen::x64::interpret(&bpf, &mut meter, vm_ptr, 0));
            remaining = meter;
            duration += start.elapsed();
    }
    println!("{:?}, remaining budget: {remaining}", duration / iters);
}

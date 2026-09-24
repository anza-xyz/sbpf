fn main() {
    let bpf = [
        191, 33, 0, 0, 0, 0, 0, 0,
        87, 1, 0, 0, 255, 3, 0, 0,
        7, 2, 0, 0, 1, 0, 0, 0,
        165, 2, 252, 255, 0x00, 0x00, 0x20, 0x00,
        149, 0, 0, 0, 0, 0, 0, 0,
    ];
    let mut duration = std::time::Duration::new(0, 0);
    let iters = 5;
    for i in 0..iters {
            let start = std::time::Instant::now();
            std::hint::black_box(solana_sbpf::codegen::x64::enter(&bpf));
            duration += start.elapsed();
    }
    println!("{:?}", duration / iters);
}

use solana_sbpf::{
    program::{BuiltinProgram, SBPFVersion},
    vm::EbpfVm,
};
use std::sync::Arc;
use test_utils::TestContextObject;

const BUDGET: u64 = 10_000_000;

fn main() {
    let bpf = [
        191, 33, 0, 0, 0, 0, 0, 0, 87, 1, 0, 0, 255, 3, 0, 0, 7, 2, 0, 0, 1, 0, 0, 0, 165, 2, 252,
        255, 0x00, 0x00, 0x20, 0x00, 149, 0, 0, 0, 0, 0, 0, 0,
    ];
    let mut duration = std::time::Duration::new(0, 0);
    let iters = 500;
    let mut remaining = 0;
    let loader = Arc::new(BuiltinProgram::new_mock());
    for _ in 0..iters {
        let mut context = TestContextObject::new(BUDGET);
        let mut vm = EbpfVm::new(loader.clone(), SBPFVersion::V3, &mut context, 0);
        vm.previous_instruction_meter = BUDGET;
        let start = std::time::Instant::now();
        std::hint::black_box(solana_sbpf::codegen::x64::interpret_and_run(
            &bpf, 0, &mut vm,
        ));
        remaining = BUDGET - vm.due_insn_count;
        duration += start.elapsed();
    }
    println!("{:?}, remaining budget: {remaining}", duration / iters);
}

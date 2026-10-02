use solana_sbpf::{
    program::{BuiltinProgram, SBPFVersion},
    vm::EbpfVm,
};
use std::sync::Arc;
use test_utils::TestContextObject;

const BUDGET: u64 = 10_000_000;

fn main() {
    let bpf = Vec::from([
        191, 33, 0, 0, 0, 0, 0, 0, 87, 1, 0, 0, 255, 3, 0, 0, 7, 2, 0, 0, 1, 0, 0, 0, 165, 2, 252,
        255, 0x00, 0x00, 0x20, 0x00, 149, 0, 0, 0, 0, 0, 0, 0,
    ]);

    // No no-ops, so that the timings are reproducible.
    let program = solana_sbpf::codegen::x64::JIT_TEMPLATES.compile(&bpf, 0);
    let code = &program.text_section;
    for b in code {
        print!("{:02X}", b);
    }
    println!();

    let mut buffer = dynasmrt::mmap::MutableBuffer::new(code.len()).unwrap();
    buffer.set_len(code.len());
    buffer.copy_from_slice(code);
    let buffer = buffer.make_exec().unwrap();
    let entrypoint = buffer.as_ptr() as usize + program.pc_section[0] as usize;

    let mut duration = std::time::Duration::new(0, 0);
    let iters = 500;
    let mut remaining = 0;
    let loader = Arc::new(BuiltinProgram::new_mock());
    for _ in 0..iters {
        let mut context = TestContextObject::new(BUDGET);
        let mut vm = EbpfVm::new(loader.clone(), SBPFVersion::V3, &mut context, 0);
        vm.previous_instruction_meter = BUDGET;
        let start = std::time::Instant::now();
        std::hint::black_box(solana_sbpf::codegen::x64::enter(
            &bpf,
            entrypoint,
            bpf.as_ptr().wrapping_add(8),
            &mut vm,
        ));
        remaining = BUDGET - vm.due_insn_count;
        duration += start.elapsed();
        assert!(matches!(
            vm.program_result,
            solana_sbpf::error::ProgramResult::Ok(_)
        ));
    }
    println!("{:?}, remaining budget: {remaining}", duration / iters);
}

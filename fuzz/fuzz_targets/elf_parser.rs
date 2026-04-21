#![no_main]

use libfuzzer_sys::fuzz_target;

use std::sync::Arc;

use solana_sbpf::{
    ebpf,
    elf::Executable,
    memory_region::MemoryRegion,
    program::BuiltinProgram,
    verifier::RequisiteVerifier,
    vm::{CallFrame, ExecutionMode},
};
use test_utils::{create_vm, TestContextObject};

fuzz_target!(|prog: &[u8]| {
    let config = solana_sbpf::vm::Config {
        enable_stack_frame_gaps: true,
        enable_symbol_and_section_labels: false,
        sanitize_user_provided_values: false,
        optimize_rodata: false,
        ..solana_sbpf::vm::Config::default()
    };

    let loader = Arc::new(BuiltinProgram::new_loader(config));

    #[allow(unused_mut)]
    let Ok(mut executable) = Executable::<TestContextObject>::from_elf(
        &prog,
        loader
    ) else {
        return;
    };
    if executable.verify::<RequisiteVerifier>().is_err() {
        return;
    }
    let mut interp_mem = vec![0u8; 1 << 16];
    let mut interp_context_object = TestContextObject::new(1 << 16);
    let interp_mem_region = MemoryRegion::new(&raw mut interp_mem[..], ebpf::MM_INPUT_START);
    create_vm!(
        interp_vm,
        &executable,
        &mut interp_context_object,
        interp_stack,
        interp_heap,
        vec![interp_mem_region],
        None
    );
    let mut interp_call_frames =
        vec![CallFrame::default(); executable.get_config().max_call_depth];
    #[allow(unused)]
    let (_interp_ins_count, interp_res) = interp_vm.execute_program(
        &executable,
        &mut ExecutionMode::Interpreted,
        &mut interp_call_frames,
    );
    #[allow(unused)]
    let interp_final_pc = interp_vm.registers[11];

    #[cfg(all(not(target_os = "windows"), target_arch = "x86_64"))]
    if executable.jit_compile().is_ok() {
        let mut jit_mem = vec![0u8; 1 << 16];
        let mut jit_context_object = TestContextObject::new(1 << 16);
        let jit_mem_region = MemoryRegion::new(&raw mut jit_mem[..], ebpf::MM_INPUT_START);
        create_vm!(
            jit_vm,
            &executable,
            &mut jit_context_object,
            jit_stack,
            jit_heap,
            vec![jit_mem_region],
            None
        );
        let (_jit_ins_count, jit_res) =
            jit_vm.execute_program(&executable, &mut ExecutionMode::Jit, &mut []);
        let jit_final_pc = jit_vm.registers[11];
        if format!("{:?}", interp_res) != format!("{:?}", jit_res) {
            let error = format!("Expected {:?}, but got {:?}", interp_res, jit_res);
            if error != "Expected Err(CallOutsideTextSegment), but got Err(ExecutionOverrun)" {
                panic!("{}", error);
            }
        }
        if interp_res.is_ok() {
            // we know jit res must be ok if interp res is by this point
            if interp_context_object.remaining != jit_context_object.remaining {
                panic!(
                    "Expected {} insts remaining, but got {}",
                    interp_context_object.remaining, jit_context_object.remaining
                );
            }
            if interp_mem != jit_mem {
                panic!(
                    "Expected different memory. From interpreter: {:?}\nFrom JIT: {:?}",
                    interp_mem, jit_mem
                );
            }

            if interp_stack != jit_stack {
                panic!(
                    "Expected different stack. From interpreter: {:?}\nFrom JIT: {:?}",
                    interp_stack, jit_stack
                );
            }

            if interp_heap != jit_heap {
                panic!(
                    "Expected different heap. From interpreter: {:?}\nFrom JIT: {:?}",
                    interp_heap, jit_heap
                );
            }
        }
        if interp_final_pc != jit_final_pc {
            panic!(
                "Expected final PC {}, but got {}",
                interp_final_pc, jit_final_pc
            );
        }
    } else {
        #[cfg(all(not(target_os = "windows"), target_arch = "x86_64"))]
        panic!("JIT compilation failed for program that passed verification");
    }

});

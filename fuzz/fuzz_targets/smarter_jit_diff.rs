#![no_main]

use libfuzzer_sys::fuzz_target;

use semantic_aware::*;
use solana_sbpf::{
    ebpf,
    elf::Executable,
    insn_builder::IntoBytes,
    memory_region::MemoryRegion,
    program::{BuiltinProgram, FunctionRegistry},
    verifier::{RequisiteVerifier, Verifier},
};
use test_utils::{create_vm, TestContextObject};

use crate::common::ConfigTemplate;

mod common;
mod semantic_aware;

#[derive(arbitrary::Arbitrary, Debug)]
struct FuzzData {
    template: ConfigTemplate,
    prog: FuzzProgram,
    mem: Vec<u8>,
}

fuzz_target!(|data: FuzzData| {
    let sbpf_version = data.template.sbpf_version;
    let prog = make_program(&data.prog, sbpf_version);
    let config = data.template.into();
    let function_registry = FunctionRegistry::default();

    if RequisiteVerifier::verify(
        prog.into_bytes(),
        &config,
        sbpf_version,
    )
    .is_err()
    {
        // verify please
        return;
    }
    #[allow(unused_mut)]
    let mut executable = Executable::<TestContextObject>::from_text_bytes(
        prog.into_bytes(),
        std::sync::Arc::new(BuiltinProgram::new_loader(config)),
        sbpf_version,
        function_registry,
    )
    .unwrap();
    let mut interp_mem = data.mem.clone();
    let mut interp_context_object = TestContextObject::new(1 << 16);
    let interp_mem_region = MemoryRegion::new_writable(&mut interp_mem, ebpf::MM_INPUT_START);
    create_vm!(
        interp_vm,
        &executable,
        &mut interp_context_object,
        interp_stack,
        interp_heap,
        vec![interp_mem_region],
        None
    );
    #[allow(unused)]
    let (_interp_ins_count, interp_res) = interp_vm.execute_program(&executable, true);
    #[allow(unused)]
    let interp_final_pc = interp_vm.registers[11];

    #[cfg(all(not(target_os = "windows"), target_arch = "x86_64"))]
    if executable.jit_compile().is_ok() {
        let mut jit_mem = data.mem.clone();
        let mut jit_context_object = TestContextObject::new(1 << 16);
        let jit_mem_region = MemoryRegion::new_writable(&mut jit_mem, ebpf::MM_INPUT_START);
        create_vm!(
            jit_vm,
            &executable,
            &mut jit_context_object,
            jit_stack,
            jit_heap,
            vec![jit_mem_region],
            None
        );
        let (_jit_ins_count, jit_res) = jit_vm.execute_program(&executable, false);
        let jit_final_pc = jit_vm.registers[11];
        if format!("{:?}", interp_res) != format!("{:?}", jit_res) {
            panic!("Expected {:?}, but got {:?}", interp_res, jit_res);
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

## Syscalls

### Traditional syscalls (SBPF versions v0, v1 and v2)

On the compiler side, syscalls are external functions to be linked during 
runtime. They must be declared as external symbols in the programming 
language. In Rust, this is done like the following code snipped.

```rust
extern "C" {
    fn sol_log_(ptr: u64, len: u64);
}
```

The goal is that such a function will appear in the shared library's dynamic 
symbol table, as below.

```
   Num:    Value          Size Type    Bind   Vis      Ndx Name
     0: 0000000000000000     0 NOTYPE  LOCAL  DEFAULT  UND
     1: 0000000000000870 49888 FUNC    GLOBAL DEFAULT    1 entrypoint
     2: 0000000000000000     0 NOTYPE  GLOBAL DEFAULT  UND sol_log_
```

Such a symbol must accompany an entry in the dynamic relocations table, 
indicating the correct offset to apply the relocation, the type of relocation 
(`R_BPF_64_32 == 0xa`), and the symbol value, like the following table.

```
DYNAMIC RELOCATION RECORDS
OFFSET           TYPE                     VALUE
000000000000d008 R_BPF_64_32              sol_log_
```

The virtual machine utilizes such information to properly load a syscall. 
While it is parsing the ELF file, it traverses the dynamic relocation table 
and resolves the `R_BPF_64_32` relocation with the steps listed below:

1. Read the relocation offset, and symbol name.
2. Check if the symbol is registered as a valid syscall.
3. Hash the symbol name using `murmur32` and writes the resulting value in the 
   relocation offset.

During execution time, when the program counter is at a syscall instruction 
(`call imm` with opcode `0x85`), it verifies if the hash in the immediate 
field of the instruction points to a syscall, and dispatches the call if that 
is the case.

The runtime makes no differentiation between an internal call and an external 
call, except for the immediate value being a registered hash. Consequently, in 
rare cases syscalls might conflict with internal calls and be treated as the 
latter.

Static syscalls are unstable and unsafe for SBPFv0, v1 and v2, because they do 
not allow ahead of time verification of syscall registration and might be 
treated as internal calls.

### Static syscalls (SBPF version v3)

In SBPFv3, static syscalls are declared in the programming language as 
function pointers to a hard-coded address. The address is the murmur32 hash of 
the syscall name. In Rust, this declaration looks like the following code 
snippet.

```rust
unsafe extern "C" fn sol_log_(message: *const u8, length: u64) {
    let syscall: extern "C" fn(*const u8, u64) = core::mem::transmute(544561597u64); // murmur32 hash of "sol_log_"
    syscall(message, length)
}
```

Static syscalls don't need any relocation, so they don't need an entry in 
neither the symbol table nor the relocation table. Likewise, during ELF 
loading there is no relocation. At verification, we check if the murmur32 hash 
points to a registered syscall that can be dispatched during execution.

For SBPFv3 there is a clear way to distinguish external and internal syscalls. 
In the `call imm` (opcode `0x85`) instruction, the source field set to zero 
means an external call and the source field set to one indicates an internal 
call. Such a distinctive feature allows static syscalls to be safe in SBPFv3.
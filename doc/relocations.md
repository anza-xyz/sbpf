## Relocations

### SBPF versions v0, v1 and v2

In early SBPF versions, the virtual machine loads the read-only data section 
and the text section to address `0x10000000`. Such an address is not reflected
in the ELF program header, and as such, the compiler must emit relocations for 
instructions that interact with symbols in either the text or the read-only 
data section.

For that, we process two types of relocations `R_BPF_64_64` (`0x1`) and 
`R_BPF_64_RELATIVE` (`0x8`). The first one indicates a relocation within the 
same section. The second indicates relocations between sections.

During ELF loading, their function is straightforward. The virtual machine 
checks if the address (addend value stored in the relocation site) is less 
than `0x100000000`. If it is not, we increment it by `0x100000000` and write 
it to the correct relocation offset.

These relocations are essential to the correct working of load instructions 
(`lddw` in particular) and indirect calls `callx`, since they ensure addresses 
represent the virtual memory layout of the execution environment.

Were these addresses not correct, programs would misbehave.

### SBPF version v3

In SBPFv3, the virtual memory is organized in such a way that the read-only 
data section is loaded into address `0x000000000` and the text section into 
address `0x100000000`. The ELF file is supposed to not have any relocation, 
so they must be resolved ahead of time.

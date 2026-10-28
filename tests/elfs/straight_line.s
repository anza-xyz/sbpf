// 32768 instructions without calls, jumps, or relocations, so that loading does nothing but
// what it does for every instruction.

    .text
    .globl entrypoint
    .type entrypoint, @function
entrypoint:
    mov64 r0, 0
    .rept 32766
    add64 r0, 1
    .endr
    exit

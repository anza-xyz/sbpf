SECTIONS
{
  .rodata 0x000000000 : {
    *(.rodata*)
    *(.data.rel.ro*)
    BYTE(0);
    . = ALIGN(8);
  } :rodata
  .text 0x100000000 : {
     *(.text*)
  } :text
  .bss.stack 0x200000000 (NOLOAD) : {
      _stack_start = .;
      . = . + 0x1000;
      _stack_end = .;
      . = ALIGN(8);
   } :stack
  .bss.heap 0x300000000 (NOLOAD) : {
        _heap_start = .;
        . = . + 0x1000;
        _heap_end = .;
        . = ALIGN(8);
   } :heap
   .strtab : { *(.strtab) } :other
  /DISCARD/ : {
      *(.comment*)
      *(.eh_frame*)
      *(*hash*)
      *(.bss*)
      *(.data*)
      *(.rel.dyn*)
      *(.dynamic)
      *(.dynsym)
      *(.dynstr)
    }
}

PHDRS
{
  rodata PT_LOAD FLAGS(4);
  text PT_LOAD FLAGS(1);
  stack PT_LOAD FLAGS(6);
  heap PT_LOAD FLAGS(6);
  dynsym PT_NULL FLAGS(0);
  other PT_NULL FLAGS(0);
}

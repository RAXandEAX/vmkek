ENTRY(_start)
PHDRS
{
 headers PT_PHDR PHDRS;
 interp PT_INTERP;
 text PT_LOAD FILEHDR PHDRS FLAGS(5);
 data PT_LOAD FLAGS(6);
 dynamic PT_DYNAMIC FLAGS(6);
 stack PT_GNU_STACK FLAGS(6);
 spare PT_NULL;
 spare2 PT_NULL;
}
SECTIONS
{
 . = 0x400000 + SIZEOF_HEADERS + 56;
 .interp : { *(.interp) } :text :interp
 .note : { *(.note.*) } :text
 .gnu.hash : { *(.gnu.hash) } :text
 .hash : { *(.hash) } :text
 .dynsym : { *(.dynsym) } :text
 .dynstr : { *(.dynstr) } :text
 .gnu.version : { *(.gnu.version) } :text
 .gnu.version_r : { *(.gnu.version_r) } :text
 .rela.plt : { *(.rela.plt) } :text
 .rela.dyn : { *(.rela.*) } :text
 .plt : { *(.plt .plt.*) } :text
 .text : { *(.text .text.*) } :text
 .rodata : { *(.rodata .rodata.*) } :text
 .eh_frame : { *(.eh_frame .eh_frame.*) } :text
 . = ALIGN(0x1000);
 .dynamic : { *(.dynamic) } :data :dynamic
 .got : { *(.got .got.*) } :data
 .data : { *(.data .data.*) } :data
 .bss : { *(.bss .bss.* COMMON) } :data
}

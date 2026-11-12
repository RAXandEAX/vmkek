ENTRY(vmk_verify_elf_bootstrap)
PHDRS { exec PT_LOAD FLAGS(5); }
SECTIONS {
  . = 0x20000000;
  .text : { *(.text .text.*) } :exec
  .rodata : { *(.rodata .rodata.*) } :exec
  .relro : { *(.data.rel.ro .data.rel.ro.* .got .got.*) } :exec
  .data : { *(.data .data.* .bss .bss.* COMMON) }
  ASSERT(SIZEOF(.data) == 0, "unexpected helper writable data/BSS")
  /DISCARD/ : { *(.eh_frame .eh_frame_hdr .note.* .comment .gcc_except_table .gcc_except_table.*) }
}

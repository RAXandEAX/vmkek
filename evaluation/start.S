.text
.globl _start
.type _start,@function
_start:
    xor %ebp, %ebp
    mov (%rsp), %rdi
    lea 8(%rsp), %rsi
    and $-16, %rsp
    call main
    mov %eax, %edi
    call *exit@GOTPCREL(%rip)
.size _start, .-_start
.section .note.GNU-stack,"",@progbits

section .text
global _start

_start:
    mov eax, 1      ; syscall: sys_exit
    xor ebx, ebx    ; exit code 0
    int 0x80        ; call kernel
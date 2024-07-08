
        .intel_syntax noprefix
        .global write, read, exit, start, _start, const_flag, key

start:
_start:
        call main
        mov rdi, 0
        jmp exit
write:
        mov rax, 1
        syscall
        ret
read:
        mov rax, 0
        syscall
        ret
exit:
        mov rax, 0x3c
        syscall
        ret


const_flag:
        .byte {flag}
        .byte 0
key:
        .byte {key}
        .byte 0

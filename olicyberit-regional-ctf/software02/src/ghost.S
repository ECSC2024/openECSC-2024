

        .intel_syntax noprefix
        .global decode_flag, flag

        .data
flag:
        .byte FLAG


        .text
decode_flag:

        mov rsi, 0x0

_loop:
        mov al, byte ptr [rdi + rsi]
        ror al, 0b1010
        xor al, 0b101010
        mov byte ptr [rdi + rsi], al

        inc rsi
        cmp rsi, 0x30
        jl _loop

        ret

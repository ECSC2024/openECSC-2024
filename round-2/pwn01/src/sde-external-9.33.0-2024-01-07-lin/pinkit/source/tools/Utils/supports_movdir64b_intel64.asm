;
; Copyright (C) 2022-2022 Intel Corporation.
; SPDX-License-Identifier: MIT
;

PUBLIC ProcessorSupportsMovdir64b

.code
ProcessorSupportsMovdir64b PROC
    push rbp
    mov  rbp, rsp
    push rax
    push rbx
    push rcx
    push rdx
    push rsi
    mov rax, 7
    xor rcx, rcx
    cpuid
    
    ; Check the 28th bit in ecx after cpuid to see if the CPU supports movdir64b
    and ecx, 8000000h
    cmp ecx, 8000000h
    jne $lNOT_SUPPORTED
    mov ecx, 0
    mov rax, 1
    jmp $lDONE3
$lNOT_SUPPORTED:
    mov rax, 0
$lDONE3:
    pop    rsi
    pop    rdx
    pop    rcx
    pop    rbx

    mov     rsp, rbp
    pop     rbp
    ret
ProcessorSupportsMovdir64b ENDP

end

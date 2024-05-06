;
; Copyright (C) 2022-2022 Intel Corporation.
; SPDX-License-Identifier: MIT
;

PUBLIC ProcessorSupportsMovdir64b

.686
.model flat, c

.code
ProcessorSupportsMovdir64b PROC
    push ebp
    mov  ebp, esp
    push eax
    push ebx
    push ecx
    push edx
    push esi
    mov eax, 7
    xor ecx, ecx
    cpuid
    
    ; Check the 28th bit in ecx after cpuid to see if the CPU supports movdir64b
    and ecx, 8000000h
    cmp ecx, 8000000h
    jne $lNOT_SUPPORTED
    mov ecx, 0
    mov eax, 1
    jmp $lDONE3
$lNOT_SUPPORTED:
    mov eax, 0
$lDONE3:
    pop    esi
    pop    edx
    pop    ecx
    pop    ebx

    mov     esp, ebp
    pop     ebp
    ret
ProcessorSupportsMovdir64b ENDP

end

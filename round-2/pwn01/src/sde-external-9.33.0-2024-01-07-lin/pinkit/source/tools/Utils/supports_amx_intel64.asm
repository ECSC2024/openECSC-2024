;
; Copyright (C) 2022-2022 Intel Corporation.
; SPDX-License-Identifier: MIT
;

PUBLIC SupportsAmx

.code
SupportsAmx PROC
    push    rbp
    mov     rbp, rsp
    push    rbx
    push    rcx
    push    rdx
    mov     rax, 1
    cpuid
    and rcx, 00c000000h
    cmp rcx, 00c000000h ; check both OSXSAVE and XSAVE feature flags
    jne $lNotSupported
                        ; processor supports AVX instructions and XGETBV is enabled by OS
    mov rcx, 0          ; specify 0 for XFEATURE_ENABLED_MASK register
                        ; 0xd0010f is xgetbv  - result in EDX:EAX
    BYTE 00Fh
    BYTE 001h
    BYTE 0D0h

    and rax, 060000h
    cmp rax, 060000h    ; check OS has enabled both XTILECFG[17] and XTILEDATA[18] state support
    jne $lNotSupported
    mov rax, 7
    mov rcx, 0          ; Check for AMX support on CPU
    cpuid
    and rdx, 01000000h  ; bit 24 amx-tile
    cmp rdx, 01000000h  ; bit 24 amx-tile
    jne $lNotSupported  ; no AMX
    mov rax, 1
    jmp $ldone

$lNotSupported:
    mov rax, 0
    jmp $ldone

$ldone:
    pop rdx
    pop rcx
    pop rbx

    mov rsp, rbp
    pop rbp
    ret


SupportsAmx ENDP

end

/*
 * Copyright (C) 2010-2022 Intel Corporation.
 * SPDX-License-Identifier: MIT
 */

#ifdef TARGET_MAC
.globl _ProcessorSupportsMovdir64b;
_ProcessorSupportsMovdir64b:
#else
.type ProcessorSupportsMovdir64b, @function
.globl ProcessorSupportsMovdir64b;
ProcessorSupportsMovdir64b:
#endif
    push %rbp
    mov  %rsp, %rbp
    push %rax
    push %rbx
    push %rcx
    push %rdx
    push %rsi

    mov $7, %rax
    xor %rcx, %rcx

    cpuid
    # Check the 28th bit in ecx after cpuid to see if the CPU supports movdir64b
    and $0x8000000, %ecx
    cmp $0x8000000, %ecx
    jne .lNOT_SUPPORTED
    mov $0, %ecx
    mov $1, %rax
    jmp .lDONE3
.lNOT_SUPPORTED:
    mov $0, %rax

.lDONE3:
    pop %rsi
    pop %rdx
    pop %rcx
    pop %rbx

    mov %rbp, %rsp
    pop %rbp
    ret


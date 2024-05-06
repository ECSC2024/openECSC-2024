/*
 * Copyright (C) 2022-2022 Intel Corporation.
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
    push %ebp
    mov  %esp, %ebp
    push %eax
    push %ebx
    push %ecx
    push %edx
    push %esi

    mov $7, %eax
    xor %ecx, %ecx

    cpuid
    # Check the 28th bit in ecx after cpuid to see if the CPU supports movdir64b
    andl $0x8000000, %ecx
    cmpl $0x8000000, %ecx
    jne .lNOT_SUPPORTED
    mov $0, %ecx
    mov $1, %eax
    jmp .lDONE3
.lNOT_SUPPORTED:
    mov $0, %eax

.lDONE3:
    pop %esi
    pop %edx
    pop %ecx
    pop %ebx

    mov %ebp, %esp
    pop %ebp
    ret


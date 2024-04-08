# OliCyber.IT - Regional CTF

## [binary] Ghost (40 solves)

This binary seems scary, it has some ghosts in it.

Author: Fabio Zoratti <@orsobruno96>

## Overview

The given binary is a compiled C program. After entering the `main` function, the program calls some other unknown functions that perform some computation on two global buffers that are initially filled with random data,

```as
│           0x004014b2      55             push rbp
│           0x004014b3      4889e5         mov rbp, rsp
│           0x004014b6      ba00010000     mov edx, 0x100              ; 256 ; uint32_t arg3
│           0x004014bb      be00424000     mov esi, 0x404200           ; uint32_t arg2
```

then the binary prints some unrelated stuff and exits.

## Solution

Static analysis is possible: one could go deep into reversing to understand the computations in the unknown functions. However, there is a much more convenient way: using dynamic analysis. We can use `gdb` to set a breakpoint immediatly after the call of these functions, right before the final print, and then examine the contents of the global buffers to get the flag.

```text
gdb> break printf
run
x/s 0x404200
flag{gdb_1s_4ctuall1_us3ful_78ca281c}
```

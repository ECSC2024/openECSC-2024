#!/usr/bin/env python3

import logging
import os
from pwn import remote

logging.disable()
# For TCP connection
HOST = os.environ.get("HOST", "localhost")
PORT = int(os.environ.get("PORT", 47007))

r = remote(HOST, PORT)
r.recvuntil(b"? ")
r.sendline(b"not_the_flag{4c1adb7e2e501fb7}")

print(r.recvline(False).split()[-1].decode())

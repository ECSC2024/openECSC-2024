#!/usr/bin/env python3

import logging
import os

from Crypto.Util.number import long_to_bytes
from pwn import remote

logging.disable()

HOST = os.environ.get("HOST", "logical.challs.external.open.ecsc2024.it")
PORT = int(os.environ.get("PORT", 38207))


def decrypt(key, enc, n):
    m = 0
    for i in range(n):
        bit = (key ^ enc) & 1
        m |= bit << i
        key = (key >> 2) | ((key & 3) << (2 * n - 2))
        enc = (enc >> 2) | ((enc & 3) << (2 * n - 2))
    return m


with remote(HOST, PORT) as chall:
    chall.sendlineafter(b"> ", b"1")
    chall.sendlineafter(b": ", b"\x00")
    chall.sendlineafter(b"> ", b"2")
    enc_flag = int(chall.recvline().decode())
    key = int(chall.recvline().decode())
    print(long_to_bytes(decrypt(key, enc_flag, key.bit_length())).decode())

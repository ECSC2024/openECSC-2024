# CyberChallenge.IT 2024 - University CTF

## [crypto] Logical (27 solves)

Another service to encrypt your notes, but this time with an additional feature: you cannot decrypt them!

`nc logical.challs.external.open.ecsc2024.it 38207`

Author: Lorenzo Demeio <@Devrar>

## Overview

In this challenge we are given an encryption function and the possibility of encrypting any message. We can also get the encryption of the flag and the goal is to decrypt it.

## Solution

Let's first understand what the encryption function is doing. The conditioned xor

```py
if note & 1:
    res ^= 1
```

is the same as computing `res ^= (note & 1)` and the line `res = (res >> 2) | ((res & 3) << (2*n-2))` rotates `res` of two bits to the right. So what `encrypt` is actually doing is xoring the `note` with the odd bits of `secret_key`.

Knowing that, if we ask for the encryption of 0, we will get in output the exact `secret_key` and with that we can decrypt the flag with the function

```py
def decrypt(key, enc, n):
    m = 0
    for i in range(n):
        bit = (key^enc) & 1
        m |= bit << i
        key = (key >> 2) | ((key & 3) << (2*n-2))
        enc = (enc >> 2) | ((enc & 3) << (2*n-2))
    return m
```

## Exploit

```py
from Crypto.Util.number import long_to_bytes
from pwn import remote
import os

HOST = os.environ.get("HOST", "logical.challs.external.open.ecsc2024.it")
PORT = int(os.environ.get("PORT", 38207))


def decrypt(key, enc, n):
    m = 0
    for i in range(n):
        bit = (key^enc) & 1
        m |= bit << i
        key = (key >> 2) | ((key & 3) << (2*n-2))
        enc = (enc >> 2) | ((enc & 3) << (2*n-2))
    return m

with remote(HOST, PORT) as chall:
    chall.sendlineafter(b"> ", b"1")
    chall.sendlineafter(b": ", b"\x00")
    chall.sendlineafter(b"> ", b"2")
    enc_flag = int(chall.recvline().decode())
    key = int(chall.recvline().decode())
    print(long_to_bytes(decrypt(key, enc_flag, key.bit_length())).decode())
```

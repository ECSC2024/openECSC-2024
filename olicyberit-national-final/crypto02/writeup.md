# OliCyber.IT 2024 - National Final

## [crypto] Choose your OTP (15 solves)

The future is already here: test this revolutionary system!

`nc chooseyourotp.challs.external.open.ecsc2024.it 38302`

Author: Matteo Protopapa <@matpro>

## Overview

The challenge simply asks for an integer $n$, then computes a random integer $0\le r \le n$ and computes the XOR between $r$ and the flag. The result is then truncated to the bit-length of n.

## Solution

Since we have complete freedom on $n$, we can send $n = 2^k$, for increasing $k$. This way, $n$ has $k+1$ bits, but the most significant one is almost always 0. Querying the server a few times gives us enough confidence on the $k$-th bit (with the leftmost one being the $0$-th), except for the first 2 bits, which can be guessed since the flag ends with `}`.

## Exploit

```python
#!/usr/bin/env python3

import logging
import os
from pwn import remote

logging.disable()

HOST = os.environ.get("HOST", "chooseyourotp.challs.external.open.ecsc2024.it")
PORT = int(os.environ.get("PORT", 1337))

flag = b'\x01'
bits = '01'

r = remote(HOST, PORT)

k = 2
while not flag.startswith(b'flag'):
    recovered = [0, 0]

    for i in range(10):
        inp = 2**k
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
```
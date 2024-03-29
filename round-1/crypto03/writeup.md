# openECSC 2024 - Round 1

## [crypto] Stealing Seeds (51 solves)

I found an interesting way to generate numbers with someone. Wanna try?

This is a remote challenge, you can connect with:

`nc stealingseeds.challs.open.ecsc2024.it 38006`

Author: Lorenzo Demeio <@Devrar>

## Overview

The goal of the challenge is to obtain the secret seed, but all we are given are two possible queries where our input is combined with `seed`, xored with a secret `k` and then hashed.

## Solution

The main idea to obtain information on `seed` is to make the two queries match on some condition on the bits of `seed`. To make them match, it is of course sufficient make the values `(seed ^ user_seed) + seed` and `(seed + user_seed) ^ seed` equal. Let's first see how these two expressions behave for specific values of `user_seed`.

In the first expression, if we send the value `user_seed = 2**256 - 1` (thus 256 bits equal 1) the result will be `(seed ^ user_seed) + seed = ~seed + seed = 2**256 - 1`, where `~seed` is the bitwise not of `seed`.

Instead, in the second expression, if we send `user_seed = 0`, we will obviously have `(seed + user_seed) ^ seed = seed ^ seed = 0`.

Now let's create two queries to obtain information on the $i$-th bit of `seed`. Since `seed` is a prime, we know that its least significant bit is 1. Let's write it as
```
seed = high_s * 2**(i + 1) + b * 2**i + low_s
```
and `user_seed` as
```
user_seed = high_us * 2**i + low_us
```
where `b` is the bit we want to find.

The first query we'll send will be
```
high_us = 2**(256 - i) - 2
low_us = 2**i - 2
```
hence
$$
\texttt{user\_seed} = \underbrace{1\ldots 10}_{256 - i \texttt{ bits}}\underbrace{1\ldots 10}_{i \texttt{ bits}}
$$
asking for the first expression. For how `low_us` is constructed we have `(low_s ^ low_us) + low_s = 2**i`. For the `high` part we have two cases:

1. `b = 1` In this case, since we have the reminder from the first expression, we have `((2*high_s + b) ^ high_us) + (2*high_s + b) + 1 = 2**(256 - i) + 1`.

2. `b = 0` In this case, we have`((2*high_s + b) ^ high_us) + (2*high_s + b) + 1 = 2**(256 - i) - 1`.

Our second query will be
```
high_us = 2**(256 - i) - 1
low_us = 0
```
asking for the second expression. Again, the `low` part is determined and is `(low_s + low_us) ^ low_s = 0`. For the `high` part we have the two cases

1. `b = 1`. Here we obtain `((2*high_s + b) + high_us) ^ (2*high_s + b) = 2**(256 - i) + (2*high_s) ^ (2*high_s + b) = 2**(256 - i) + 1`.

2. `b = 0`. In this case the value of `((2*high_s + b) + high_us) ^ (2*high_s + b)` will depend on the lower bits of `high_s`, but for sure it will be greater o equal than `2**(256 - i)` and thus different from the second case of the previous query.

Hence, to obtain the value of `seed`, we can make these two queries for each bit and set it to one if the two queries match and to 0 if they are different

## Exploit

```python
import os
from pwn import *
import logging
logging.disable()

HOST = os.environ.get("HOST", "localhost")
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
```

# openECSC 2024 - Round 3

## [crypto] LazyDH (99 solves)

I'm too lazy to generate my DH exponents from zero. I've saved some secure ones and just modify those.

Author: Lorenzo Demeio <@Devrar>

## Overview

In this challenge we are given a first Diffie-Hellman key exchange where we know both the public keys $g^a$ and $g^b$ and the shared secret $g^{ab}$. Then a second key exchange is executed, with the same Bob's secret key $b$, but with a new Alice secret key $a_1$, computed by adding 1 to every digit of $a$.

The goal is to compute the new shared secret $g^{a_1b}$ to decrypt the flag.

## Solution

Let's write $a_1$ as $a_1 = a + k$, where we don't know $k$ yet. Then the new shared secret can be computed as:

$$
g^{a_1b} = g^{(a + k)b} = g^{ab}\cdot g^{kb} = g^{ab}\cdot (g^b)^k.
$$

Since we know both $g^{ab}$ and $g^b$, if we can compute $k$ we can find the new shared secret.

### Computing k

Since the digits of $a_1$ are computed as

```py
a1_digits = [(d + 1) % 10 for d in a_digits]
```

we can see that the difference $k = a_1 - a$ will have almost all digits 1, with the exception of the positions where $a$ has a 9 (actually, if the most significant digit of $a$ is a 9, $k$ will be negative and will have a different form, but we can continue hoping this is not the case).

Let's see what happens when $a$ has a sequence of consecutive 9s, like

$$
a = \ldots d9999\ldots
$$

with $d \neq 9$. Then $a_1$ will be of the form

$$
a_1 = \ldots (d+1)0000\ldots
$$

and

$$
k = \ldots 00001\ldots
$$

At this point, we can just guess the positions of the 9s in $a$ and compute $k$ accordingly or just brute force the positions of the 0s in $k$ directly. For each guess, we compute the new shared secret and try to decrypt the flag.

Since $a$ is of 128 bits, it will have around 5 or 6 digits 9, so the brute force won't take much time.

## Exploit

```py
from Crypto.Util.Padding import pad, unpad
from Crypto.Cipher import AES
from hashlib import sha256
from Crypto.Util.number import long_to_bytes
import itertools

with open("lazydh.txt") as rf:
    p = int(rf.readline().split(" = ")[1])
    ga = int(rf.readline().split(" = ")[1])
    gb = int(rf.readline().split(" = ")[1])
    shared = int(rf.readline().split(" = ")[1])
    enc_flag = bytes.fromhex(rf.readline().split(" = ")[1][1:-2])

q = (p-1)//2
g = 2
while pow(g, q, p) != 1:
    g += 1


len_a = len(str(2**128))
k = int("1"*len_a)

for i in range(len_a):
    for idxs in itertools.combinations(range(len_a), r=i):
        tmp_k = k - sum(10**idx for idx in idxs)
        guess_new_shared = (shared*pow(gb, tmp_k, p)) % p
        key = sha256(long_to_bytes(guess_new_shared)).digest()
        cipher = AES.new(key, AES.MODE_ECB)
        flag = cipher.decrypt(enc_flag)
        if b"flag" in flag:
            print(unpad(flag, AES.block_size).decode())
            exit()
```

# OliCyber.IT 2024 - Regional CTF

## [crypto] Random Cycles (4 solves)

Knowing the key it's easy to decrypt. This time it will be harder.

Author: Lorenzo Demeio <@Devrar>

## Overview

In this challenge we are not given the key for the decryption, but we have 10 queries where we can choose the ciphertext. After that we have to decrypt a random ciphertext for 100 times.

## Solution

Our goal is to retrieve the secret key with the 10 given queries. Let $n_c$ be the random number associated to the character $c$ in the key.

In the first challenge we've seen that, at every $i$-th step of the encryption, the $i$-th char of the plaintext remains unchanged, therefore, by choosing a plaintext with all different characters, we can obtain information on $n_c$ for each $c$ in the plaintext in the following way:

- Let's suppose that we send the plaintext
    `abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWX`.
- The output will be something like
  `aNihEPVAwqnMOILXHFcvTUsjdefGJbQpWrDzklSKmuyxtgCRoB`.
- Since from the second step on the character `N` has never changed position, we know that it has arrived in the second position at the first step.
- Since it's initial index was 39, we know that $n_a = 11 \mod{49}$.
- We can proceed with the same reasoning obtaining information on $n_N \mod{48}$, $n_i \mod{47}$, $n_h \mod{46}$ and so on.

To obtain the exact value of each $n_c$ we need to combine the information from different queries. If we have different equations of the form $n_a = k_1 \mod{m_1}$ and $n_a = k_2 \mod{m_2}$, using CRT we can obtain $n_a \mod{\text{lcm}(m_1, m_2)}$. By taking random plaintexts with all different characters, with high probability we'll have enough equations to get each $n_c$ modulo a number greater than 50, thus it's exact value (the queries can be obtimized, but we have enough queries to use this simpler approach).

Once we have the `key`, we can easily decrypt each message as we've seen in the previous challenge.

## Exploit

```py
import os
from pwn import remote
import random
import string
import math
from sympy.ntheory.modular import crt 

HOST = os.environ.get("HOST", "localhost")
PORT = int(os.environ.get("PORT", 34001))

alph = string.ascii_letters + string.digits
n = 50

def spin(w, n):
    n = n % len(w)
    return w[-n:] + w[:-n]

def decrypt(ct, key):
    pt = ct
    for i in range(n-1, 0, -1):
        k = key[pt[i-1]]
        pt = pt[:i] + spin(pt[i:], -k)
    return pt

chall = remote(HOST, PORT)

key = {x: [(0, 1)] for x in alph}

for _ in range(10):
    payload = ''.join(random.sample(alph, n))

    chall.sendlineafter(b": ", payload.encode())
    ans = chall.recvline().decode().split(": ")[1].strip()

    tmp = payload
    for i in range(n-2):
        k = n-i-1 - tmp[i+1:].index(ans[i+1])
        key[tmp[i]].append((k, n-i-1))
        tmp = tmp[:i+1] + spin(tmp[i+1:], k)

my_key = {x: int(crt([y[1] for y in key[x]], [y[0] for y in key[x]])[0]) % int(math.lcm(*[y[1] for y in key[x]])) for x in alph}

for _ in range(100):
    ct = chall.recvline().decode().split(": ")[1].strip()

    pt = decrypt(ct, my_key)
    chall.sendlineafter(b": ", pt.encode())

print(chall.recvline().decode())
```

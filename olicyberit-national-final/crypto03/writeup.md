# OliCyber.IT 2024 - National Final

## [crypto] Keyless Signatures (2 solves)

If I don't give you any keys you can't forge anything... Right?

`nc keyless.challs.external.open.ecsc2024.it 38300`

Author: Matteo Rossi <@mr96>

## Overview

The challenge exposes a service with 3 possible options:
1. signing something for a chosen user, except the user `admin`
2. verifying yourself, giving your username and a signature of `Verifying myself: I am {user} on OliCyber.IT`, where `user` is your username
3. sending a message to a chosen user; this will return the response of the user, that is always `ACK`, and its corresponding signature (with the recipient's user key)

The objective is to verify as `admin`.

_Note: this challenge has (at least) 3 possible solutions found during development and testing. We will report all 3 of them in the writeup for completeness._

## Solution 1 (intended solution)
Let's analyze the verify function: given a signature $(s_1, s_2)$, it tests if

$$
s_2^e \equiv h(u)s_1^{h(m)} \pmod{n}
$$

where $u$ is the username for which the message is verified, $m$ is the message and $h$ is the sha256 hash function. We will ignore the signing function for the moment, since it is not needed for this solution.

From option 3 we can get a signature of `ACK` from the admin. Let's call this signature $(s_1, s_2)$. By using the extended gcd algorithm, we can find two coefficients $a$ and $b$ such that

$$
a\cdot e - b\cdot h(m_t) = -h(m_a)
$$

where $m_t$ is the target message (the verifying one for the admin) and $m_a$ is simply `ACK`. At this point we take $s_1' = s_1^e$ and $s_2'=s_2s_1^a$. The new pair is a valid signature for $m_t$. In fact substituting in the verifying equation we have that the check becomes

$$
(s_2s_1^a)^e \equiv h(u)s_1^{b\cdot h(m_t)} \pmod{n}
$$

that, bringing the term in $s_1$ to the LHS and using our identity, we can see that it is the exact same check as the one for $m_a$, and so it verifies correctly for the admin user.

## Solution 2 (found in testing by @Devrar)
For this second solution, we need to know how the signing function works. Given a message $m$ and a user $u$ it samples a random number $r$ and the signature is $(s_1, s_2) = (r^e, h(u)^d\cdot r^{h(m)})$, where $d$ is the private exponent (as in RSA) of the public key $(N, e)$ of the server.

### Recovering $h(u)^d$
From the first query we can obtain signatures for any user $u$ different from `admin` and any message $m$. Let $m$ be such that $h(m) = 0 \pmod{e}$ and $(s_1, s_2) = (r^e, h(u)^d\cdot r^{h(m)})$; in this case we can recover the value of $h(u)^d$ by computing

$$
s_2\cdot s_1^{\frac{h(m)}{e}} \pmod{n}.
$$

### Recovering the random $r$ from query 3
Let $u$ be a user for which we have recovered $h(u)^d$ as explained in the previous step. We can know use the third query to recover a random value $r$ used for the signature of `ACK`. Let $(s_1, s_2) = (r^e, h(u)^d\cdot r^{h(m_a)})$. Since we know $h(u)^d$ we can recover the value of $r^{h(m_a)}$. Since $\gcd(e, h(m_a)) = 1$, by Bezout's identity we can find $a, b$ such that $a\cdot e + b\cdot h(m_a) = 1$. We can then compute

$$
(r^e)^a \cdot (r^{h(m_a)})^b \pmod{n} = r^{a\cdot e + b\cdot h(m_a)} = r \pmod{n} = r,
$$

since $r < n$.

### Breaking the random
The random numbers $r$ are obtained through the `random` module of python, which uses Mersenne Twister algorithm, that is not cryptographically secure. Hence, once we retrive enough obsarvations of $r$ with the previous step, we are able to recover the Mersenne Twister state and predict future values of $r$.

### Crafting the final signature
Now that we know the values of $r$ used in query 3, we can simply send a message to `admin` and recover $h(u_a)^d$ (the admin user) by diving $s_2$ by $r^{h(m_a)}$ (which is possible since we know $r$).

At this point we can forge the signature for the message $m_t$ selecting a random value $r$ and returning

$$
(s_1, s_2) = (r^e, h(u_a)^d\cdot r^{h(m_t)}).
$$

Finally we verify the signature and get the flag.

## Solution 3 (found in testing by @PhiQuadro)

This solution is similar to the first one in structure, but it uses the fact that we know the admin's username.

Let's solve $a\cdot h(m_t)+1 = e\cdot b$. At this point we have that, similarly to solution 1, $s_1 = h(u_a)^a \pmod{n}$ and $s_2 = h(u_a)^b \pmod{n}$ does the job.

## Exploit (for solution 1)
```py
#!/usr/bin/env python3

import logging
import os
from pwn import remote
from hashlib import sha256

logging.disable()

def h(m):
    return int.from_bytes(sha256(m).digest(), "big")

def extended_gcd(aa, bb):
    lastremainder, remainder = abs(aa), abs(bb)
    x, lastx, y, lasty = 0, 1, 1, 0
    while remainder:
        lastremainder, (quotient, remainder) = remainder, divmod(lastremainder, remainder)
        x, lastx = lastx - quotient*x, x
        y, lasty = lasty - quotient*y, y
    return lastremainder, lastx * (-1 if aa < 0 else 1), lasty * (-1 if bb < 0 else 1)

HOST = os.environ.get("HOST", "localhost")
PORT = int(os.environ.get("PORT", 38300))

r = remote(HOST, PORT)

pk = r.recvline()
n = int(pk.split()[-2][1:-1])
e = 65537

r.recvuntil(b"> ")
r.sendline(b"3")
r.recvuntil(b": ")
r.sendline(b"test")
r.recvuntil(b": ")
r.sendline(b"admin")
r.recvlines(2)
sig = r.recvline()
s1 = int(sig.split()[-2][1:-1])
s2 = int(sig.split()[-1][:-1])

# a*e - b*h("I am...") = -h("ACK")

to_forge = h(b"Verifying myself: I am admin on OliCyber.IT")
base = h(b"ACK")

g, c1, c2 = extended_gcd(e, -to_forge)
c1 *= -base
c2 *= -base
s1f = pow(s1, c2, n)
s2f = (s2*pow(s1, c1, n)) % n

r.recvuntil(b"> ")
r.sendline(b"2")
r.recvuntil(b": ")
r.sendline(b"admin")
r.recvuntil(b": ")
r.sendline(str(s1f).encode())
r.recvuntil(b": ")
r.sendline(str(s2f).encode())
print(r.recvline())
```

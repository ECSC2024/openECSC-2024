# TeamItaly Preselection CTF 2024

## [crypto] No Misuse (3 solves)

No weak random: ✅
No nonce reuse: ✅
Perfect security: ✅

`nc nomisuse.challs.external.open.ecsc2024.it 38319`

Author: Matteo Rossi <@mr96>

## Overview

The challenge gives us a signature scheme based on elliptic curves. Given a (hashed) message $m$, signatures are computed as pairs $(s_1,s_2)$, with

$$
s_1 \equiv a+mc-k\pmod{q}, s_2\equiv b+md+kx^{-1} \pmod{q},
$$

where $(a,b,c,d,x)$ is the private key and $k$ is a nonce. The verification algorithm checks if $s_1G+s_2H = U+V$, where $G$ is the curve base point, $H=xG$, $U=aG+bH$ and $V=cG+dH$. Our objective is crafting 10 signatures for random given messages, having access to a signing oracle for chosen (distinct) messages for 5 times.

## Solution

### Recovering x

Given three signatures $(s_1, s_2)$, $(r_1, r_2)$ and $(t_1, t_2)$ for messages $m_1, m_2$ and $m_3$ respectively, we can write (by just writing down the equations and adding them together):
$$
((r_1-s_1)(m_1-m_2)^{-1} - (t_1-s_1)(m_1-m_3)^{-1})\cdot x \equiv ((s_2-r_2)(m_1-m_2)^{-1} - (t_1-s_1)(m_1-m_3)^{-1}) \pmod{q}
$$

from which we can easily recover $x$ computing a modular inverse.

### Recovering the rest of the private key

Once we have $x$ we can write

$$
a + b\cdot x + c\cdot m + d\cdot m\cdot x \equiv s_1+x\cdot s_2 \pmod{q}
$$

for 4 different messages $m$ (we can reuse the previous 3 and ask for another query) and then solve the linear system to obtain $(a,b,c,d)$. Once we solved the system of equations we can simply start the challenge and sign locally the given inputs.

## Exploit

```py
from pwn import process
from hashlib import sha256

def sign(m):
    chall.sendlineafter(b": ", m.encode())
    s1, s2 = tuple(map(int, chall.recvline(False).decode().split(": ")[1][1:-1].split(", ")))
    return s1, s2

def H(msg):
    return int.from_bytes(sha256(msg).digest(), 'big')

def real_sign(msg, a, b, c, d, x):
        h_msg = H(msg)
        k = 1

        s1 = (a + h_msg*c - k) % q
        s2 = (b + h_msg*d + k*pow(x, -1, q)) % q

        return (s1, s2)

q = 115792089210356248762697446949407573529996955224135760342422259061068512044369
HOST = os.environ.get("HOST", "nomisuse.challs.external.open.ecsc2024.it")
PORT = int(os.environ.get("PORT", 38319))

with remote(HOST, PORT) as chall:
    chall.recvline().decode()
    chall.recvline().decode()

    s0 = sign("0")
    s1 = sign("1")
    s2 = sign("2")
    s3 = sign("3")

    m0 = H(b"0")
    m1 = H(b"1")
    m2 = H(b"2")
    m3 = H(b"3")

    rhs = ((s1[0] - s0[0])*pow(m0 - m1, -1, q) - (s2[0] - s0[0])*pow(m0 - m2, -1, q)) % q
    lhs = ((s0[1] - s1[1])*pow(m0 - m1, -1, q) - (s0[1] - s2[1])*pow(m0 - m2, -1, q)) % q
    hope_x = (rhs*pow(lhs, -1, q)) % q
    
    A = matrix(GF(q), [[1, hope_x, m0, m0*hope_x], [1, hope_x, m1, m1*hope_x], [1, hope_x, m2, m2*hope_x], [1, hope_x, m3, m3*hope_x]])
    v = vector(GF(q), [s0[0] + hope_x*s0[1], s1[0] + hope_x*s1[1], s2[0] + hope_x*s2[1], s3[0] + hope_x*s3[1]])

    a, b, c, d = list(map(int, A.solve_right(v)))

    sign("4")

    for _ in range(10):
        msg = bytes.fromhex(chall.recvline().decode().split(": ")[1])
        s1, s2 = real_sign(msg, a, b, c, d, hope_x)
        chall.sendlineafter(b": ", str(s1).encode())
        chall.sendlineafter(b": ", str(s2).encode())

    print(chall.recvline().decode())
```

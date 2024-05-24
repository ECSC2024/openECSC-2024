# openECSC 2024 - Round 3

## [crypto] LWE2048 (35 solves)

Larger moduli are more secure, right?

`nc lwe2048.challs.open.ecsc2024.it 38018`

Author: Riccardo Zanotto <@Drago>

## Overview

The challenge server samples a modulus $n$ and a secret vector $s$ of integers modulo $n$. Then for each query it outputs an "[LWE sample](https://en.wikipedia.org/wiki/Learning_with_errors)" $\langle x, s\rangle + e\pmod n$, where $x$ is a user provided vector, and $e$ is an "error" term.

Notice that if the vector $x$ was randomly generated, then the LWE assumption states that even with small-ish errors it would be infeasible to recover the secret $s$ from the samples. However, the vulnerability here is in the fact that the user can provide his own queries.

## Solution

The main idea is that, fixing the product $h=\langle x_0, s\rangle$, it is possible to recover the wanted linear combination of the secret values with 2048 queries, given that the error term is smaller than $n/(3*2048)$. By obtaining 4 different linear combinations we can then solve for the secret.

We will now simplify the oracle to operate on scalars, and thus of the form $t\mapsto t\cdot h+e\pmod n$, where $t$ is just a number. This oracle can be obtained from the challenge oracle by querying $t\cdot x_0$.

Now, the idea is simply to query the values $t=1,2,4,\dots, 2^{2047}$, obtaining the values $v_i = 2^ih+e_i\pmod n$, and then doing a "binary search" recovering $h$ bit by bit.

Indeed, the high bit of $v_0=h+e_0\pmod n$ will most likely be the high bit of $h$, because the error is small, and the modular reduction will not do anything. Then for $v_1=2h+e_1\pmod n$ we know the high bit of $h$, so we subtract the according multiple of $n$ and repeat the process of setting the next highest bit of h to the value being smaller or bigger than $n/2$. By continuing this process, we can recover all of $h$.

Alternatively, notice that $v_{i+1}-2v_i\equiv 2^{i+1}h+e_{i+1}-2^{i+1}h-2e_i\equiv e_{i+1}-2e_i\pmod n$; however, since the error is small, then there will be no reduction modulo $n$ (if we consider representatives in $[-n/2,n/2]$). In particular, setting $A$ to be the matrix

$$
    \begin{pmatrix}
    -2 & 1 & 0 & \dots & 0\\
    0 & -2 & 1 & \dots & 0\\
    \vdots & \vdots & \ddots & \dots & \vdots\\
    0 & \dots & 0 & -2 & 1\\
    n_0 & n_1 & n_2 & \dots & n_k
    \end{pmatrix}
$$

where $n_k\dots n_1n_0=n$ is the binary representation of $n$, we can see that $A\cdot(1,2,\dots,2^k)\equiv0\pmod n$, and thus $$A\cdot (v_0,\dots,v_k)\equiv A\cdot((1,2,\dots,2^k)h+(e_0,\dots,e_k))\equiv A\cdot(e_0,\dots,e_k)$$

However, since all errors are bounded by $n/(3*k)$, in the last multiplication of $A\cdot (e_0,\dots,e_k)$ there is no modular reduction happening.

So, in order to compute the error vector, we can compute $z=A\cdot (v_0,\dots,v_k)\pmod n$, and solve the linear system over the integers $A\cdot (e_0,\dots,e_k)=z$.

## Exploit

```python
from pwn import remote, process, os

nbits = 2048
HOST = os.environ.get("HOST", "lwe2048.challs.open.ecsc2024.it")
PORT = int(os.environ.get("PORT", 38018))

def solve():
    with remote(HOST, PORT) as chall:
        chall.recvline()
        n = int(chall.recvline(False).decode().split(' ')[-1])

        vecs = [[1,1,1,1], [1,2,1,1], [1,1,2,1], [1,1,1,2]]
        rr = []

        for base in vecs:
            print(f"Recovering combination {base}")
        
            mul = 1
            h_guess = 0
            overflows = 0
            start = False
            for i in range(nbits):
                h_guess <<= 1

                arr = [mul*bi for bi in base]
                chall.sendline(",".join(map(str, arr)).encode())
                out = int(chall.recvline(False).decode().split(' ')[-1])
                h_guess |= (((out + n*overflows) >> (nbits-1)) & 1)

                if start:
                    overflows *= 2

                if out > n//2:
                    if not start:
                        start = True

                    overflows += 1

                mul *= 2
            print("Recovered h_guess")
            rr.append(h_guess)

        for _ in range(10000-nbits*4):
            chall.sendline(b"1,1,1,1")
            chall.recvline()

        s1 = (rr[1]-rr[0]) % n
        s2 = (rr[2]-rr[0]) % n
        s3 = (rr[3]-rr[0]) % n
        s0 = (rr[0]-(s1+s2+s3)) % n

        s = f"{s0},{s1},{s2},{s3}"
        chall.sendline(s.encode())
        flag = chall.recvline(False).decode().strip().split(' ')[-1]

    return flag

print(solve())
```

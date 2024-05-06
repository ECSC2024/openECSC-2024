# openECSC 2024 - Round 2

## [crypto] MathMAC (36 solves)

Why using boring symmetric crypto for MACs when we can use fancy math?

`nc mathmac.challs.open.ecsc2024.it 38013`

Author: Riccardo Zanotto <@Drago>

## Overview

This challenge implements a MAC, and allows users to get random pairs of (message, tag). The objective is to forge a tag for a new message.

We can notice that the MAC is actually the [Naor-Reingold PRF](https://en.wikipedia.org/wiki/Naor%E2%80%93Reingold_pseudorandom_function), defined by $$f_a(x)=g^{a_0a_1^{x_1}\cdots a_n^{x_n}}\pmod p,$$ where $a=(a_0,\dots,a_n)$ is a vector of integers, and $x_1,\dots,x_n$ are the bits of the input $x\in\{0,1\}^n$.

## Solution

The vulnerability lies in the fact that the prime $p$ has only 64 bits, so it's very easy to compute discrete logarithms in $\mathbb F_p$.

This means that given a message-tag pair $(x,t)$, by computing the dlog of $t$ with respect to $g$ we obtain the value $a_0a_1^{x_1}\cdots a_n^{x_n}\pmod q$, where $q=\frac{p-1}2$.

If we were allowed to choose our values of $x$, we could ask the values $[0,0,\dots,0]$, $[1,0,\dots,0]$ and $[0,1,0,\dots,0]$ and thus compute $a_0$, $a_0a_1$ and $a_0a_2$ respectively. From this we could compute the tag $a_0a_1a_2$ for the new message $[1,1,0,\dots,0]$.

Unfortunately, the server chooses the messages for us. However, this just means that by asking many tokens we get a lot of different products of different subsets of $a_i$, and by combining them via linar algebra we can recover $a_0$ for example, and send $(0, g^{a_0})$ as the new message.

Indeed, suppose that we recover

$$\begin{align*}
v_1 &\equiv a_0a_1^{x^1_1}\cdots a_n^{x^1_n}\pmod q,\\ 
v_2 &\equiv a_0a_1^{x^2_1}\cdots a_n^{x^2_n}\pmod q,\\
\vdots\\
v_m &\equiv a_0a_1^{x^m_1}\cdots a_n^{x^m_n}\pmod q
\end{align*}$$

Then, by carefully choosing $e_1,\dots,e_m$ we could compute $a_0\equiv v_1^{e_1}\cdots v_m^{e_m}\pmod q$.

In order to find these exponents, we just have to find solutions to the equation

$$a_0\equiv \left(a_0a_1^{x^1_1}\cdots a_n^{x^1_n}\right)^{e_1}\cdots \left(a_0a_1^{x^m_1}\cdots a_n^{x^m_n}\right)^{e_m}\pmod q$$

It is enough to then impose the linear system

$$\begin{align*}
e_1+\dots+e_m &= 1,\\ 
e_1x^1_1 + \dots + e_mx^m_1 &= 0,\\
\vdots\\
e_1x^1_n + \dots + e_mx^m_n &= 0
\end{align*}$$

Notice that this is a linear system modulo $\varphi(q)=q-1$, since the unknowns originally were in the exponent.

## Exploit

```python
class Client:
    def __init__(self):
        self.r = remote(HOST, PORT)
        self.r.recvline()

    def get_token(self):
        self.r.sendlineafter("> ", "1")
        data = self.r.recvline(False).decode()
        x, tag = data.split(",")
        return int(x), int(tag)
    
    def validate_token(self, x, tag):
        self.r.sendlineafter("> ", "2")
        self.r.sendline(f"{x},{tag}")
        return self.r.recvline(False).decode()

p = 8636821143825786083
K = GF(p)
g = K(4)

q = (p-1)//2
R = Zmod(q-1)


def solve():
    client = Client()

    M = 64
    A = []
    tags = []
    for _ in range(2*M):
        x, tag = client.get_token()
        x = list(map(int, bin(x)[2:].zfill(M)))
        A.append([1] + x)
        tags.append(tag)

    for i in range(M):
        B = Matrix(R, A[i:i+M+1])
        if gcd(B.det(), q-1) == 1:
            ttags = tags[i:i+M+1]
            break
    print("Got values, computed matrix")

    logs = [K(t).log(g) for t in ttags]
    print("Computed dlogs")

    Binv = B^(-1)

    row = Binv[0]
    res = GF(q)(1)
    for vi, ti in zip(row, logs):
        res *= GF(q)(ti)^int(vi)

    forged_tag = g^res
    print("Recovered secret")

    flag = client.validate_token(0, forged_tag)
    return flag

flag = solve()
print(flag)
```
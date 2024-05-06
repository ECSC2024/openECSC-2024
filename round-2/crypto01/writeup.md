# openECSC 2024 - Round 2

## [crypto] Invention (25 solves)

Inventing hash functions based on elliptic curves is not easy, but now I found out that with the quadratic twist I can lift any x! This should be enough to create a secure one.

Note: the challenge is running with SageMath 10.2 on the remote server.

`nc invention.challs.open.ecsc2024.it 38011`

Author: Lorenzo Demeio <@Devrar>

## Overview

The challenge implements a register/login system where the password is hashed using an elliptic curve hash that lifts the blocks of the message as points on a curve $E$ or its quadratic twist $ET$.

The goal is to login as the admin. We know his password, but the user is blocked, so we have to first register as another user and then find a second preimage of the hash function with a given prefix. 

## Solution

The first step of the challenge is to register a user with a password starting with a prefix block $`B_0`$ given by the server. The blocks we chose for the password will be important for creating the collision, since the only allowed blocks at login are the ones stored in `safe_blocks`.

Let the blocks of the admin password `pass` be $`A_0, A_1, A_2`$. Then its hash is computed as the pair of points

```math
h(pass) = (A_0 \cdot P_u + E.lift_x(A_2),\; A_1 \cdot PT_u)
```

or

```math
h(pass) = (A_0 \cdot P_u,\; A_1 \cdot PT_u + ET.lift_x(A_2)),
```

depending on the fact if $`A_2`$ is lifted on $`E`$ or on $`ET`$. Let's suppose the hash is of the first kind (we can retry multiple time until it happens).

Since, at login, the user is retrived from the password dictionary as `user_pwds[pwd_hash]`, if we are able to find a second preimage `pass_2` of $`h`$ with prefix $`B_0`$, we can login as our previoulsy registered user and password `pass_2` and the system will identify us as the admin.

To simplify the collision, we can use some of the blocks of the admin password and construct `pass_2` in the form $`B_0, A_1, B_2, \ldots, B_n, A_2`$, with each $`B_i`$ being lifted on $`E`$ and not on $`ET`$ for $`i \in \{2, \ldots, n\}`$. This way, the hash of `pass_2` will look like

```math
h(pass_2) = \left(B_0 \cdot P_u + \sum_{i=2}^n E.lift_x(B_i) + E.lift_x(A_2),\; A_1\cdot PT_u \right),
```

thus, to have $`h(pass_2) = h(pass)`$, we need to have

```math
\sum_{i=2}^n E.lift_x(B_i) = (A_0 - B_0) \cdot P_u = (A_0 - B_0)k_1 \cdot G.
```

The other important constraint is given by the fact that the server decodes the password to check for the correct prefix and this means that all its characters have to be ascii.

The idea for finding the right blocks $`B_i`$ is to precompute offline some points $`C_i = h_i \cdot G`$ such that their $`x`$ coordinate has all ascii characters. Since the prime over which the curve is defined has 160 bits (i.e. 20 bytes), the probability of this happening by taking random $`h_i`$ is approximately $`\frac{1}{2^{20}}`$, which is easily doable.

Once we have such points, our goal is to find a linear combination of them such that

```math
\sum l_i\cdot C_i = (A_0 - B_0)\cdot P_u = (A_0 - B_0)\cdot k_1 \cdot G
```

and construct the password as

```math
pass_2 = B_0, A_1, \underbrace{C_0[x], \ldots, C_0[x]}_{l_0 \text{times}},  \underbrace{C_1[x], \ldots, C_1[x]}_{l_1 \text{times}}, \ldots, A_2.
```

We have to concatenate the points $`l_i`$ times, since computing the actual point $`l_i \cdot C_i`$ will break the property that the x coordinate is all composed of ascii characters. For this reason we need the $`l_i`$ to be small so that the length of `pass_2` is small enough to be stored in memory, sent to the server and hashed (for this reason the trivial combination $`l_0 = (A_0 - B_0)\cdot k_1 \cdot h_0^{-1}`$ its not suitable for our case, since the size of `pass_2` would be of the order of $`2^{160}`$ bytes).

To find a combination with small $`l_i`$ we can use the LLL reduction on the matrix

```math
\begin{pmatrix}
1 & 0 & 0 & \ldots & 0 & h_0 & 0\\
0 & 1 & 0 & \ldots & 0 & h_1 & 0\\
 &  &  & \vdots &  &  & \\
0 & 1 & 0 & \ldots & 1 & h_n & 0\\
0 & 0 & 0 & \ldots & 0 & (A_0 - B_0)\cdot k_1 & t\\
0 & 0 & 0 & \ldots & 0 & q & 0\\
\end{pmatrix}
```

with an appropriate $`t`$, where $`q`$ is the order of $`G`$.

Once we've found small enough $`l_i`$ we can construct the password as above and login as the admin.

## Exploit

```python
from Crypto.Util.number import bytes_to_long, long_to_bytes
import os
from pwn import remote
from itertools import combinations

HOST = os.environ.get("HOST", "invention.challs.open.ecsc2024.it")
PORT = int(os.environ.get("PORT", 38011))

p = 0xffffffffffffffffffffffffffffffff7fffffff
N = p.bit_length()//8
F = GF(p)
a = F(0xffffffffffffffffffffffffffffffff7ffffffc)
b = F(0x1c97befc54bd7a8b65acf89f81d4d4adc565fa45)
E = EllipticCurve(F, (a, b))
G = E(0x4a96b5688ef573284664698968c38bb913cbfc82, 0x23a628553168947d59dcc912042351377ac5fb32)
n = 0x0100000000000000000001f4c8f927aed3ca752257
E.set_order(n)

d = F(1)
while d.is_square():
    d += 1

nt = 0xfffffffffffffffffffe0b3706d8512b358adda9
ET = E.quadratic_twist(d)
ET.set_order(nt)
GT = ET.gens()[0]

def hash_block(M, Ci, CTi):
    try:
        Pm = E.lift_x(M)
        Ci += Pm
    except:
        Pm =  ET.lift_x(M*d*4)
        CTi += Pm
    return Ci, CTi

def elliptic_hash(Pu, PTu, m):
    assert len(m) >= 2*N

    if len(m) % N != 0:
        pad_length = N - (len(m) % N)
        m += b"\x80"
        m += b"\x00"*(pad_length-1)

    m_blocks = [ZZ(bytes_to_long(m[i:i+N])) for i in range(0, len(m), N)]

    k0 = m_blocks[0]
    k1 = m_blocks[1]


    Ci = k0*Pu
    CTi = k1*PTu

    for i in range(2, len(m_blocks)):
        Ci, CTi = hash_block(m_blocks[i], Ci, CTi)

    return Ci, CTi

# precomputed p160 points
hs = [1217026089109958965601498719303868517806436843678, 759448250872938908677880028896924254805920193388, 569173398545399153150935989280567361233052263967, 1199332692307752283550912627888456483713217610524, 1079027481086532546300937867602186580109338741185, 1069059598553897685855916305006912095069249705224, 288315851873985034955567433589056437908480638959, 12045287124509758747086019002237774348075329126, 864117480199393342910610778363331267214279559672, 776470851910979264466357554533884486586230065570, 125353821621861442391960712727526298446557293195, 678687985152159619473210367825117510967511359391, 708868983378893084885762006582760347810790708333, 1456821013185649722962670579831626142255403649699, 1087880777291130166057466480619109904235474963817, 1157573364993699351931989005203835939365433852923, 114689096430069459590931860024621684190362406651, 1146550305237141315493982764352276847601544061131, 365275067682288802773719966114934668167985864518, 1084568201469664034342141842730256563547003724763, 747398271589005252059207252040131711215995514190, 1027179285114999715411727668473724213549647450584, 601844635799634280083241679791178199170445676818]

xs = {h : long_to_bytes(int((h*G).xy()[0])) for h in hs}

def find_comb(hs, target):
    n_qs = len(hs)
    m = [[1 if i == j else 0 for i in range(n_qs + 2)] for j in range(n_qs + 2)]
    for i in range(n_qs):
        m[i][-2] = hs[i]
    m[n_qs][-2] = target
    m[n_qs][-1] = 2**100
    m[-1][-2] = G.order()
    m[-1][-1] = 0

    M = matrix(ZZ, m)
    M.rescale_col(n_qs, 2**500)

    M1 = M.LLL()
    for row in M1:
        if abs(row[-1]) == 2**100 and row[-2] == 0:
            if (all(x <= 0 for x in row[:-2]) and row[-1] > 0) or (all(x >= 0 for x in row[:-2]) and row[-1] < 0):
                return row[:-2]
    return None

if __name__ == "__main__":
    with remote(HOST, PORT) as chall:
        k1 = int(chall.recvline().decode().split(" = ")[1])
        k2 = int(chall.recvline().decode().split(" = ")[1])

        Pu = k1*G
        PTu = k1*GT

        username = "ciao"
        pwd = b"a"*N + b"".join(xs.values())

        chall.recvline()
        chall.recvline()

        chall.sendlineafter(b": ", username.encode())
        token = chall.recvline().decode().strip().split()[-1]

        chall.sendlineafter(b": ", (token.encode() + pwd).hex().encode())
        chall.recvline()
        admin_pwd = bytes.fromhex(chall.recvline().decode().split("'")[-2])
        admin_pwd_blocks = [admin_pwd[i:i+N] for i in range(0, len(admin_pwd), N)]

        C1, CT1 = elliptic_hash(Pu, PTu, admin_pwd)

        prefix = token.encode()

        payload_blocks = [prefix, admin_pwd_blocks[1]]

        target = ((bytes_to_long(admin_pwd_blocks[0]) - bytes_to_long(payload_blocks[0]))*k1) % G.order()

        for used_hs in combinations(hs, r=12):
            comb = find_comb(used_hs, target)
            if comb != None:
                break

        for c, h in zip(comb, used_hs):
            payload_blocks += [xs[h] for _ in range(abs(c))]

        payload_blocks += admin_pwd_blocks[2:]

        payload = b"".join(payload_blocks)

        chall.sendlineafter(b": ", username.encode())
        chall.sendlineafter(b": ", payload.hex().encode())
        flag = chall.recvline().decode().strip().split()[-1]

        print(flag)
```


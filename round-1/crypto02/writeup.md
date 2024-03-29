# openECSC 2024 - Round 1

## [crypto] Another Matrix KE (15 solves)

Tired of key exchange schemes on weird groups with random operations? Let's go back to our good old matrices!

This is a remote challenge, you can connect with:

`nc anothermatrixke.challs.open.ecsc2024.it 38009`

Authors: Lorenzo Demeio <@Devrar>, Matteo Rossi <@mr96>

## Overview

The key exchange implemented in the challenge is a variant of Stickel's key exchange.

## Solution
The [original attack](https://shpilrain.ccny.cuny.edu/stickel_attack.pdf) finds an invertible matrix $X$ and a matrix $Y$ that satisfy the system
$$
X \cdot A = A \cdot X\\
Y\cdot B = B\cdot Y\\
X\cdot U = W\cdot Y
$$

by solving a linear system with $2\cdot dim^2$ unknowns. With $X$ and $Y$ we can compute the shared matrix
$$
key = X^{-1} \cdot V \cdot Y = X^{-1} \cdot R \cdot W \cdot S \cdot Y = R \cdot X^{-1} \cdot W \cdot Y \cdot S = R \cdot U \cdot S.
$$

In our case, $A$ and $B$ are non-invertible, thus the system above will never have an invertible solution $X$. A cryptanalysis of the non-invertible case was presented by Mullan [here](https://www.researchgate.net/publication/267178269_Cryptanalysing_variants_of_Stickel's_key_agreement_scheme), where the main idea is to substitute the third equation of the above system with $X \cdot U = q(A)\cdot W \cdot Y$ where $q(x)$ is the gcd between the minimal polynomial of $A$ and $l(x)$, the secret polynomial such that $l(A) = L$.

In the case described in the paper, the polynomial $q(x)$ has to be bruteforced, since they work on the original ring chosen by Stickel ($\mathbb{F}_q$ with $q = 2^k$) and $q(x)$ is likely to have factors different from $x$. But working on $Z_{2^k}$, $q(x)$ will be $x$ with very high probability, so there is no bruteforce to be done in our case.

The last problem to solve is that solving the system on $Z_{2^k}$ is not easy. To overcome this, as suggested in Mullan's paper, it is possible to solve it bit by bit: we first consider it on $\mathbb{F}_2$ and find a solution $X_0$; we then write $X = 2\cdot X_1 + X_0$ and find the value of $X_1 \mod{2}$ and so on until we've found all the bits of $X$.

In some cases the matrix $X$ won't be invertible, but since this is determined only by $X \mod{2} = X_0$, we can stop at the first step and try with another instance.

Once we've found a solution $X, Y$, similarly as before, we can find the shared key as 
$$
key = X^{-1} \cdot A \cdot V \cdot Y = R \cdot U \cdot S
$$
and decrypt the flag.

## Exploit

```python
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
from hashlib import sha256
from pwn import remote
import logging
logging.disable()

dim = 15
k = 50
n = 2**k

Zn = Zmod(n)

Mn = MatrixSpace(Zn, dim)

def solve_eqs(coeff_matrix, cur_sol, exp):
    constant_terms = []
    for row in coeff_matrix:
        ct = int(-sum(ci * si for ci, si in zip(row, cur_sol)))
        assert ct % 2**exp == 0
        constant_terms.append(ct//2**exp)

    coeff_matrix_mod2 = coeff_matrix.change_ring(GF(2))
    constant_terms = vector(GF(2), constant_terms)

    if exp == 0:
        print("Looking for invertible X")
        for v in coeff_matrix_mod2.right_kernel():
            X = matrix(GF(2), dim, dim, list(v[:dim**2]))
            if X.is_invertible():
                sol = v
                break
        else:
            print("Nope")
            return None
    else:

        sol = coeff_matrix_mod2.solve_right(constant_terms)

    sol = [2**(exp)*int(sol[i]) + cur_sol[i] for i in range(len(sol))]

    assert all(int(x) % 2**(exp+1) == 0 for x in coeff_matrix*vector(Zn, sol))

    return sol

HOST = os.environ.get("HOST", "localhost")
PORT = int(os.environ.get("PORT", 38009))

for _ in range(50):
    try:
        chall = remote(HOST, PORT)

        A = Mn(sage_eval(chall.recvline().decode().strip().split(" = ")[1]))
        B = Mn(sage_eval(chall.recvline().decode().strip().split(" = ")[1]))
        W = Mn(sage_eval(chall.recvline().decode().strip().split(" = ")[1]))
        U = Mn(sage_eval(chall.recvline().decode().strip().split(" = ")[1]))
        V = Mn(sage_eval(chall.recvline().decode().strip().split(" = ")[1]))
        enc_secret = chall.recvline().decode().split(" = ")[1]

        Q = PolynomialRing(Zn, dim**2*2, "v")
        v = Q.gens()
        PolMatrixSpace = MatrixSpace(Q, dim)

        A1 = PolMatrixSpace(A)

        X = PolMatrixSpace([[v[i] for i in range(dim*j, dim*(j+1))] for j in range(dim)])
        Y = PolMatrixSpace([[v[dim**2 + i] for i in range(dim*j, dim*(j+1))] for j in range(dim)])

        B1 = PolMatrixSpace(B)

        eq1 = X*A1 - A1*X
        eq2 = Y*B1 - B1*Y
        eq3 = A1*W*Y - X*U

        coeff_matrix = []

        print("Building coefficient matrix...")
        for i in range(dim):
            for j in range(dim):
                coeff_matrix.append([eq1[i][j].coefficient(v[k]) for k in range(dim**2*2)])
                coeff_matrix.append([eq2[i][j].coefficient(v[k]) for k in range(dim**2*2)])
                coeff_matrix.append([eq3[i][j].coefficient(v[k]) for k in range(dim**2*2)])

        coeff_matrix = matrix(Zn, coeff_matrix)

        X = zero_matrix(Zn, dim)
        Y = zero_matrix(Zn, dim)

        while not X.is_invertible():
            print("Solving system")

            cur_sol = [0 for _ in range(coeff_matrix.ncols())]
            for exp in range(k):
                cur_sol = solve_eqs(coeff_matrix, cur_sol, exp)

            for i in range(dim):
                for j in range(dim):
                    X[i, j] = Zn(cur_sol[dim*i + j])

            for i in range(dim):
                for j in range(dim):
                    Y[i, j] = Zn(cur_sol[dim**2 + dim*i + j])


        assert A*X == X*A
        assert B*Y == Y*B
        assert A*W*Y == X*U

        key = X.inverse() * A * V * Y
        key = sha256(str(key).encode()).digest()
        cipher = AES.new(key, AES.MODE_ECB)
        secret = unpad(cipher.decrypt(bytes.fromhex(enc_secret)), AES.block_size).decode()

        chall.sendlineafter(b"? ", secret.encode())
        flag = chall.recvline().decode().strip()
        print(flag)
        chall.close()
        break
    except:
        chall.close()
```

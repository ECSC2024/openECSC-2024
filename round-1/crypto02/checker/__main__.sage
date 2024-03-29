#!/usr/bin/env sage

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

HOST = os.environ.get("HOST", "anothermatrixke.challs.open.ecsc2024.it")
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
        Coso = MatrixSpace(Q, dim)

        A1 = Coso(A)

        X = Coso([[v[i] for i in range(dim*j, dim*(j+1))] for j in range(dim)])
        Y = Coso([[v[dim**2 + i] for i in range(dim*j, dim*(j+1))] for j in range(dim)])

        B1 = Coso(B)

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
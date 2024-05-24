#!/usr/bin/env python3
import logging

from pwn import remote, os

logging.disable()

nbits = 2048
HOST = os.environ.get("HOST", "lwe2048.challs.open.ecsc2024.it")
PORT = int(os.environ.get("PORT", 38018))


def solve():
    with remote(HOST, PORT) as chall:
        chall.recvline()
        n = int(chall.recvline(False).decode().split(' ')[-1])

        vecs = [[1, 1, 1, 1], [1, 2, 1, 1], [1, 1, 2, 1], [1, 1, 1, 2]]
        rr = []

        for base in vecs:
            mul = 1
            h_guess = 0
            overflows = 0
            start = False
            for i in range(nbits):
                h_guess <<= 1

                arr = [mul * bi for bi in base]
                chall.sendline(",".join(map(str, arr)).encode())
                out = int(chall.recvline(False).decode().split(' ')[-1])
                h_guess |= (((out + n * overflows) >> (nbits - 1)) & 1)

                if start:
                    overflows *= 2

                if out > n // 2:
                    if not start:
                        start = True

                    overflows += 1

                mul *= 2

            rr.append(h_guess)

        for _ in range(10000 - nbits * 4):
            chall.sendline(b"1,1,1,1")
            chall.recvline()

        s1 = (rr[1] - rr[0]) % n
        s2 = (rr[2] - rr[0]) % n
        s3 = (rr[3] - rr[0]) % n
        s0 = (rr[0] - (s1 + s2 + s3)) % n

        s = f"{s0},{s1},{s2},{s3}"
        chall.sendline(s.encode())
        flag = chall.recvline(False).decode().strip().split(' ')[-1]

    return flag


for _ in range(20):
    try:
        flag = solve()
        if flag is None:
            continue
        print(flag)
        break
    except:
        continue

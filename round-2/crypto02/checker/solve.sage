import os
import logging

os.environ["PWNLIB_NOTERM"] = "True"
logging.disable()

from pwn import remote, process

HOST = os.environ.get("HOST", "mathmac.testing.internal")
PORT = int(os.environ.get("PORT", 38013))

REMOTE = True

class Client:
    def __init__(self):
        if REMOTE:
            self.r = remote(HOST, PORT)
        else:
            self.r = process(["python3", "../src/chall.py"])
        self.r.recvline()

    def get_token(self):
        self.r.sendlineafter(b"> ", b"1")
        data = self.r.recvline(False).decode()
        x, tag = data.split(",")
        return int(x), int(tag)
    
    def validate_token(self, x, tag):
        self.r.sendlineafter(b"> ", b"2")
        self.r.sendline(f"{x},{tag}".encode())
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

    # print("Got values, computed matrix")

    logs = [K(t).log(g) for t in ttags]
    # print("Computed dlogs")

    Binv = B^(-1)

    row = Binv[0]
    res = GF(q)(1)
    for vi, ti in zip(row, logs):
        res *= GF(q)(ti)^int(vi)

    forged_tag = g^res
    # print("Recovered secret")

    flag = client.validate_token(0, forged_tag)
    return flag


flag = solve()
print(flag)
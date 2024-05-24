from Crypto.Util.Padding import pad, unpad
from Crypto.Cipher import AES
from hashlib import sha256
from Crypto.Util.number import long_to_bytes
import itertools

with open("output.txt") as rf:
    p = int(rf.readline().split(" = ")[1])
    ga = int(rf.readline().split(" = ")[1])
    gb = int(rf.readline().split(" = ")[1])
    shared = int(rf.readline().split(" = ")[1])
    enc_flag = bytes.fromhex(rf.readline().split(" = ")[1][1:-2])

q = (p-1)//2
g = 2
while pow(g, q, p) != 1:
    g += 1


len_a = len(str(2**128))
k = int("1"*len_a)

for i in range(len_a):
    for idxs in itertools.combinations(range(len_a), r=i):
        tmp_k = k - sum(10**idx for idx in idxs)
        guess_new_shared = (shared*pow(gb, tmp_k, p)) % p
        key = sha256(long_to_bytes(guess_new_shared)).digest()
        cipher = AES.new(key, AES.MODE_ECB)
        flag = cipher.decrypt(enc_flag)
        if b"openECSC" in flag:
            print(unpad(flag, AES.block_size).decode())
            exit()
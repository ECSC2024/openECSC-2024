import os
# from cvc5.pythonic import *
import random
from tqdm import trange, tqdm
from pwn import process, remote
import time

BITS = 32
MASK = (1<<BITS) - 1
r1 = 19
r2 = 29
m1 = 3
m2 = 5
mod = 1 << BITS

RC = [2667589438, 3161395992, 3211084506, 3202806575, 827352482, 3632865942, 1447589438, 3161338992]

def ROL(x, r):
    return ((x << r) | ((x >> (BITS - r)))) & MASK

def ROR(x, r):
    return ((x >> r) | ((x << (BITS - r)))) & MASK

def ADD(x, y):
    return (x+y) & MASK

def MUL(x, y):
    return (x*y) & MASK

def SUB(x, y):
    return (x-y) & MASK

def round_f(x, k, i):
    return MUL(3, ROL(ADD(k, x), 19)) ^ MUL(5, ROL(SUB(k, x), BITS-29)) ^ ADD(k, MUL(i, 0x13371337))

def key_schedule(key_l, key_r, n_rounds):
    keys = []
    keys.append(key_l)

    for i in range(n_rounds - 2):
        tmp = key_l
        key_l = key_r
        key_r = ADD(tmp, round_f(key_r, RC[i], i+1))
        keys.append(key_l)

    keys.append(key_r)
    return keys

def encrypt_block(l, r, round_keys, n_rounds):
    for i in range(n_rounds):
        l, r = r, ADD(l, round_f(r, round_keys[i], i+1))
    return l, r

def decrypt_block(l, r, round_keys, n_rounds):
    for i in range(n_rounds):
        l, r = SUB(r, round_f(l, round_keys[i], n_rounds-i)), l
    return l, r

def reverse_key_schedule(key_l, key_r, n_rounds):
    keys = [key_r]
    for i in range(n_rounds - 2):
        tmp = key_r
        key_r = key_l
        key_l = SUB(tmp, round_f(key_l, RC[n_rounds - 3 - i], n_rounds-2-i))
        keys.append(key_r)
    keys.append(key_l)
    return keys[::-1]

def generate_pts(diff_l, diff_r, tot):
    pts = []
    for i in range(tot):
        pt1_l, pt1_r = i, random.getrandbits(32)
        pt2_l, pt2_r = ADD(pt1_l, diff_l), ADD(pt1_r, diff_r)
        pts.append((pt1_l, pt1_r))
        pts.append((pt2_l, pt2_r))
    return pts

def filter_cts_1round(pts, cts, diff):
    filtered_pts = []
    filtered_cts = []
    for i in range(0, len(cts), 2):
        if SUB(cts[i+1][0], cts[i][0]) == diff:
            filtered_pts.append(pts[i])
            filtered_pts.append(pts[i+1])
            filtered_cts.append(cts[i])
            filtered_cts.append(cts[i+1])

    return filtered_pts, filtered_cts

def get_pairs(diff_l, diff_r, num_pairs, chall):
    pts = generate_pts(diff_l, diff_r, num_pairs)
    long_pts = [str((pt[0] << 32) | pt[1]).encode() for pt in pts]
    payload = b"\n".join(long_pts)
    tic = time.time()
    print("Sending plaintexts")
    chall.sendline(payload)
    chall.sendline(b"-1")
    print("Done")

    print("Receiving...")
    roba = chall.recvuntil(b"Ke").decode()
    toc = time.time()
    cts = roba.splitlines()[:-1]
    cts = [tuple(map(int, ct.split(", "))) for ct in cts]
    assert len(cts) == len(pts)
    print("Done")
    print(f"Connection time: {int(toc - tic)}")

    return pts, cts


diff_l = 268431360
diff_r = 0
num_pairs = 7000000//2 - 1
n_rounds = 10
num_conn = 0
while True:
    with remote("juniorfeistel.challs.open.ecsc2024.it", "38014") as chall:
        chall.recvline()
        print()
        num_conn += 1
        pts, cts = get_pairs(diff_l, diff_r, num_pairs, chall)
        filtered_pts, filtered_cts = filter_cts_1round(pts, cts, diff_l)
        print(f"Total candidates: {len(filtered_pts)//2}")
        if len(filtered_pts)//2 < 3:
            continue
        print(f"Connections: {num_conn}")
        with process(["./brute_keys"]) as brute_cpp:
            tic = time.time()
            brute_cpp.sendline(str(len(filtered_pts)).encode())
            for i in range(0, len(filtered_pts)):
                brute_cpp.sendline(str(filtered_pts[i][0]).encode())
                brute_cpp.sendline(str(filtered_pts[i][1]).encode())
                brute_cpp.sendline(str(filtered_cts[i][0]).encode())
                brute_cpp.sendline(str(filtered_cts[i][1]).encode())
            num_k1 = int(brute_cpp.recvline().decode().split(": ")[1])
            print(f"{num_k1 = }")

            if num_k1 > 20 or num_k1 == 0:
                continue

            print(f"Connections: {num_conn}")
            key_r, key_l = tuple(map(int, brute_cpp.recvline().decode().split()))
            print(f"{key_r = }")
            print(f"{key_l = }")
            hope_keys = reverse_key_schedule(key_l, key_r, n_rounds)
            print(f"{hope_keys = }")
            toc = time.time()
            print(f"Time: {int(toc - tic)}")

        chall.sendlineafter(b"?\n", str((hope_keys[0] << 32) | hope_keys[1]).encode())
        print(chall.recvline().decode())
        print(chall.recvline().decode())
        break

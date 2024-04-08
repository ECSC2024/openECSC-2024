#!/usr/bin/env python3
import os
from random import getrandbits
from Crypto.Util.Padding import pad
from datetime import datetime


flag = os.getenv('FLAG', 'flag{redacted}')
ROUNDS = 10


def xor(a, b):
    return bytes([x^y for x,y in zip(a,b)])


def add(a, b):
    return int.to_bytes((int.from_bytes(a, 'big') + int.from_bytes(b, 'big')) & ((1 << 128) - 1), 16, 'big')


def rol(x, n):
   return int.to_bytes(((int.from_bytes(x, 'big') << n) | (int.from_bytes(x, 'big') >> (128 - n))) & ((1 << 128) -1), 16, 'big')


def ror(x, n):
   return rol(x, 128-n)


def prng(n, seed, iterations):
  numbers = []
  for _ in range(iterations):
    seed = (seed ** 2) % n
    numbers.append(seed)
  return numbers


def encrypt_block(key, block):
    assert len(key) == 32
    assert len(block) == 32
    k2, k1 = key[:16], key[16:32]
    b1, b2 = block[:16], block[16:]
    for r in range(ROUNDS):
        b2 = add(b1, b2)
        b2 = xor(b2, k2)
        b1 = ror(b1, 31)
        b1 = xor(b1, k1)
    return b1 + b2


def encrypt(key, msg):
    padded = pad(msg, 32)
    encrypted = b''
    for i in range(len(padded) // 32):
        encrypted += encrypt_block(key, padded[32*i:32*i+32])
    return encrypted




if __name__ == "__main__":
    n = getrandbits(2048)
    print(f'{n = }')

    # integer between 0 and 999999, I hope it is enough
    seed  = datetime.now().microsecond

    key = int.to_bytes(prng(n, seed, 10)[-1], 2048//8, 'big')[16:16+32]

    enc = encrypt(key, flag.encode())
    print(f'enc = bytes.fromhex("{enc.hex()}")')
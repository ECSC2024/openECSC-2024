#!/usr/bin/env python3

import os
import string
import random

flag = os.getenv('FLAG', 'flag{redacted}')


alph = string.ascii_letters + string.digits
n = 50
key = {x : random.randint(0, n-1) for x in alph}

def spin(w, k):
    k = k % len(w)
    return w[-k:] + w[:-k]

def encrypt(w, key):
    for i in range(1, len(w)):
        w = w[:i] + spin(w[i:], key[w[i-1]])
    return w

for _ in range(10):
    s = input("Plaintext: ")
    if len(s) != n:
        break
    print(f"Ciphertext: {encrypt(s, key)}")


for _ in range(100):
    pt = ''.join(random.choice(alph) for _ in range(n))
    print(f"Ciphertext: {encrypt(pt, key)}")
    guess = input("Plaintext: ")
    if guess != pt:
        print("Nope")
        exit()

print(flag)
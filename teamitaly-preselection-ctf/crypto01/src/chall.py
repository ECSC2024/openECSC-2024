#!/usr/bin/env python3

import os
from fastecdsa.curve import P256
from Crypto.Random.random import randint
from hashlib import sha256

flag = os.getenv('FLAG', 'TeamItaly{redacted}')

class Signer:
    def __init__(self):
        self.g = P256.G
        self.q = P256.q
        self.x = randint(2,self.q-1)
        self.h = self.x * self.g
        self.a = randint(2,self.q-1)
        self.b = randint(2,self.q-1)
        self.c = randint(2,self.q-1)
        self.d = randint(2,self.q-1)

        self.u = self.a * self.g + self.b * self.h
        self.v = self.c * self.g + self.d * self.h

        self.public_key = (self.u, self.v)
        self.private_key = (self.a, self.b, self.c, self.d, self.x)
    
    def H(self, msg):
        return int.from_bytes(sha256(msg).digest(), 'big')
    
    def sign(self, msg):
        h_msg = self.H(msg)
        k = randint(2,self.q-1)

        s1 = (self.private_key[0] + h_msg*self.private_key[2] - k) % self.q
        s2 = (self.private_key[1] + h_msg*self.private_key[3] + k*pow(self.private_key[4], -1, self.q)) % self.q

        return (s1, s2)
    
    def verify(self, msg, signature):
        s1, s2 = signature
        h_msg = self.H(msg)

        return s1*self.g + s2*self.h == self.u + h_msg*self.v

S = Signer()
print(f"u = {(S.public_key[0].x, S.public_key[0].y)}")
print(f"v = {(S.public_key[1].x, S.public_key[1].y)}")

signed = []

for _ in range(5):
    msg = input("Please enter your message: ")
    if msg not in signed:
        print(f"Here's your signature: {S.sign(msg.encode())}")
        signed.append(msg)
    else:
        print("Really? You already have that one...")


for _ in range(10):
    target = os.urandom(32)
    print(f"Target message: {target.hex()}")
    s1 = int(input("First component of the signature: "))
    s2 = int(input("Second component of the signature: "))

    if not S.verify(target, (s1,s2)):
        print("Wrong!")
        exit()
print(flag)
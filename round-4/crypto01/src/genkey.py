#!/usr/bin/env python3

from Crypto.PublicKey import RSA
from Crypto.Util.number import isPrime, getPrime

nbits = 256
k = 16

def getMyPrime(nbits, k):
    p = 1
    while not isPrime(p):
        p = getPrime(nbits)**k - 2
    return p

p = getMyPrime(nbits, k)
q = getMyPrime(nbits, k)
n = p*q
e = 0x10001

key = RSA.construct((n, e))

with open('key.pem', 'wb') as wf:
    wf.write(key.public_key().export_key())
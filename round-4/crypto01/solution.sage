#!/usr/bin/env sage

from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Util.number import isPrime, getPrime, bytes_to_long

nbits = 256
k = 16

e = 0x10001
exec(open("prettyprimes_output.txt", "r").read())

xy = int(Integer(n).n(2000).nth_root(k))

R.<z> = PolynomialRing(ZZ, "z")

coef = (xy**k + 4 - n)//2
f = z**(2*k) - coef*z**k + xy**k

x = f.roots()[0][0]

p = x**k - 2
q = n//p
d = pow(e, -1, (p-1)*(q-1))

flag = PKCS1_OAEP.new(RSA.construct(tuple(map(int, (n, e, d))))).decrypt(bytes.fromhex(c))
print(flag.decode())
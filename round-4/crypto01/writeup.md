# openECSC 2024 - Final Round

## [crypto] PrettyPrimes (33 solves)

My primes are so pretty!

Authors: Francesco Felet <@PhiQuadro>, Lorenzo Demeio <@Devrar>

## Overview

In this challenge we are given an RSA public key and a ciphertext.

The challenge is static and the flag is encrypted with proper padding (OAEP), therefore the only solution path available is to exploit the custom prime generation to factor the modulus: $p$ and $q$ are of the form $x^{16} - 2$ where $x$ is a 256 bit random prime.

## Solution

Let $p = (x^{16} - 2)$ and $q = (y^{16} - 2)$.

The approximate 16th root of $n$ leaks the product $xy$. Indeed if we rewrite $n$ as:

$$ n = x^{16}y^{16} \cdot \left( 1 - \frac{2(x^{16} + y^{16}) - 4}{x^{16}y^{16}} \right) $$

and consider the size of $x$ and $y$, we can notice that the correction term is really small.

We can then use this information to recover $\varphi(n)$ in multiple ways, for example if we compute the sum:

$$ x^{16} + y^{16} = \frac{(xy)^{16} + 4 - n}{2} $$

we obtain $x$ and $y$ as the integer roots of the polynomial

$$ f(z) = z^{32} - (x^{16} + y^{16})z^{16} + (xy)^{16} $$

and factor $n$.

## Exploit

```py
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
```
# openECSC 2024 - Round 1

## [crypto] Spiky Crypto (36 solves)

There are so many weird groups you can use for a key exchange. I just took one with a funny name.

Authors: Lorenzo Demeio <@Devrar>, Matteo Rossi <@mr96>

## Overview
The key exchange implemented is an adaptation of Anshel-Anshel-Goldfeld key exchange on Braid group to the Cactus group.

## Solution
The public keys $`b_1`$ and $`a_1`$ are the conjugation of $`b`$ and $`a`$ with the secret keys $`A`$ and $`B`$. So, calling $`x = b[0]`$ and $`y = b_1[0]`$, we have $`y = A^{-1} \cdot x \cdot A`$. Moreover, $`A`$ is equal to the product of some random elements of $`a`$ (which we know): $`A = a[{sa_0}] \cdot a[sa_1] \cdot \ldots \cdot a[sa_{L-1}]`$. In the end we have:

```math
y = a[sa_{L-1}]^{-1} \cdot \ldots \cdot a[sa_1]^{-1} \cdot a[sa_0]^{-1} \cdot x \cdot a[{sa_0}] \cdot a[sa_1] \cdot \ldots \cdot a[sa_{L-1}].
```

We can now try to guess each $`a[sa_i]`$ at a time, by conjugating $`y`$ for each element of $`a`$. Indeed, when we conjugate for the right element $`a[sa_{L-1}]`$ we get

```math
a[sa_{L-1}] \cdot y \cdot a[sa_{L-1}]^{-1} = a[sa_{L-2}]^{-1} \cdot \ldots \cdot a[sa_0]^{-1} \cdot x \cdot a[{sa_0}] \cdot \ldots \cdot a[sa_{L-2}].
```

With a statistical analysis, we can observe that, when we conjugate an element $`x`$ by an element $`a`$ and normalize, the result will be significantly longer than $`x`$ (where the length is the number of generators in its representation). So, in the equation above, since $`x`$ is conjugated with less elements then before, we can expect the result to be shorter after the normalization. Instead, if we conjugate with an element different from $`a[sa_{L-1}]`$, the result will be longer.

Once we found $`a[sa_{L-1}]`$ we can repeat the procedure to obtain all the $`a[sa_i]`$ and thus the secret key $`sa`$. With this we can then conclude the key exchange and decrypt the flag.

In the script below the `__mul__` and `__invert__` functions of the Cactus group are not patcher, so `_normalize()` is called after each operation.

## Exploit

```python
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
from hashlib import sha256

output_file = open("public.txt", "r")

n = 10
N1 = 20
N2 = 20
L1 = 5
L2 = 8
L = 15

Jn = groups.misc.Cactus(n)
s = Jn.group_generators()

a = eval(output_file.readline().split(" = ")[1])
b = eval(output_file.readline().split(" = ")[1])
b1 = eval(output_file.readline().split(" = ")[1])
a1 = eval(output_file.readline().split(" = ")[1])

def my_len(elem):
    return len(str(elem).split("*"))

b1 = b1[0]

my_sa = []

for _ in range(L):
    min_len = my_len(b1)
    cur_best = None
    for i in range(N1):
        hope = a[i]*b1*a[i]**-1
        if my_len(hope) < min_len:
            cur_best = i
            min_len = my_len(hope)
    my_sa.append(cur_best)
    b1 = a[cur_best]*b1*a[cur_best]**-1

sa = my_sa[::-1]
A = prod(a[i] for i in sa)

shared_a = A**-1 * prod(a1[i] for i in sa)

ciphertext = output_file.readline()

key = sha256(str(shared_a).encode()).digest()
cipher = AES.new(key, AES.MODE_ECB)
flag = unpad(cipher.decrypt(bytes.fromhex(ciphertext)), AES.block_size).decode()
print(flag)
```

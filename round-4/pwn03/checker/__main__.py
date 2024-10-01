#!/usr/bin/env python3
#
# @mebeim - 2024-09-12
#

import os
import sys
from base64 import b64encode
from pathlib import Path
from re import compile

from pwn import context, remote


HOST = os.getenv('HOST', 'backfired.challs.open.ecsc2024.it')
PORT = int(os.getenv('PORT', 47003))
FLAG_EXP = compile(rb'openECSC\{[^}]+\}')


def run(b64script: bytes) -> bool:
	with context.local(log_level='error'):
		r = remote(HOST, PORT)

		line = r.recvline()
		if b'do hashcash' in line.lower():
			r.sendlineafter(b'Result: ', 'redacted'.encode())
		else:
			r.unrecv(line)

	r.recvuntil(b'done.\n')
	r.sendline(b64script)
	r.sendline(b'EOF')

	output = r.recvall()
	with context.local(log_level='error'):
		r.close()

	if not output:
		return False

	match = FLAG_EXP.search(output)
	if match is None:
		return False

	print(match.group().decode())
	return True


if __name__ == '__main__':
	with (Path(__file__).parent / '../src/expl.js').open('rb') as f:
		expl = b64encode(f.read())

	for _ in range(16):
		if run(expl):
			break
	else:
		sys.exit('Exceeded max attempts')

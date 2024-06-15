# OliCyber.IT 2024 - National Final

## [binary] Dragon fighters club (8 solves)

Beat all the dragons to join our exclusive club! People say it's unfeasible... I say you can find a way :P

`nc dragonfightersclub.challs.external.open.ecsc2024.it 38303`

Author: Giulia Martino <@Giulia>

## Overview

The challenge is a binary game that lets you fight dragons. Both you and the dragons have life points; when you fight a dragon, you can only beat those whose life points are less than yours. Whenever you beat a dragon, your life points are increased by the dragon's life points and you can chose to inflict it an arbitrary amount of damage points.  

When you manage to bring all the dragons' life points to zero, a `win` function is called, which gives you the flag. One of the dragons has a very high amount of points, so it is realistically unfeasible to win only playing legit.

The users are provided with the challenge binary together with a `docker-compose.yml` file useful to deploy the challenge locally.

## Vulnerability

The dragons are implemented with a very simple C structure. From the source code:

```c
struct dragon {
    char *name;
    unsigned long hp;
};

struct dragon dragons[10] = {
    {.name = "Fire Dragon", .hp = 0x100},
    {.name = "Ice Dragon", .hp = 0x200},
    {.name = "Earth Dragon", .hp = 0x300},
    {.name = "Wind Dragon", .hp = 0x500},
    {.name = "Water Dragon", .hp = 0x1a00},
    {.name = "Electric Dragon", .hp = 0x3000},
    {.name = "Metal Dragon", .hp = 0x4500},
    {.name = "Dark Dragon", .hp = 0xa000},
    {.name = "Light Dragon", .hp = 0x14000},
    {.name = "Poison Dragon", .hp = 0x7fffffffffffffff},
};
```

The function `fight` lets us select one of the available dragons and fight it. The code parses a signed char (`hhd`) from stdin using `scanf` and then uses it as an index for the array `dragons`.

```c
    if (scanf("%hhd", &choice) != 1)
            die("Invalid choice");
        
        dragon = &dragons[choice];
```

The problem is no checks are performed on the variable `choice`, which can therefore be used to access the `dragons` array out of bounds.

## Solution

The missing check lets us use whatever index we want, as long as it fits in a `signed char`. By selecting an out of bounds index, the program will interpret the memory found at that index as if it was a `struct dragon`, so:
- the first 8 bytes found will be interpreted as a pointer to the dragon's name.
- the second 8 bytes found will be interpreted as the dragon's life points.

Considering when a dragon is beaten we can arbitrarily chose an amount of damage points, if we manage to align a dragon properly, we can arbitrarily modify the 8 bytes corresponding to its life points by subtracting them the arbitrary damage.

The `dragons` array is stored inside the `.bss` section, which is in memory just a bit after the GOT section. The GOT stores the memory location of functions imported from external libraries, for example `libc`. The binary is `Partial RELRO`, meaning its GOT is writable and functions' addresses are resolved the first time the functions are called. When a program calls an external function for the first time, its GOT entry points inside the executable itself, to a dedicated code stub needed to compute the real function's address inside the external library. Once its address inside the external library is computed (resolved), it is written back inside the GOT.

```
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

If we align a `struct dragon` on the GOT, we can then use the damage points to modify one of its entries to make it point to a different location, possibly the `win` function. The next time that function is called, the program will actually call the `win` function.

Among all the possible GOT entries, the `exit` one is very convenient: the function's address has not been resolved yet so its entry points inside the binary itself and its value is relatively close to `win`'s address. By using a negative value for the dragon index (namely -5) we can align a dragon on the GOT so that the 8 bytes corresponding to the dragon's life points are aligned with the `exit` GOT entry.

If we directly try to fight it though, we will realize we cannot beat it, because we need our life points to be bigger than `exit`'s GOT address. We can just start our exploit by fighting multiple times the other dragons, so that we can increase our life points to an amount sufficient to beat the GOT `exit` dragon.

We then just need to compute the distance between the `exit`'s unresolved GOT entry address and `win` function. By beating the dragon and setting the arbitrary damage value to this distance, we will modify the `exit` entry to point to `win`. And then we can just exit the program.

## Exploit

You can check the full exploit [here](checker/__main__.py).

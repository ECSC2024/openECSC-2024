# openECSC 2024 - Final Round

## [rev] Reflect (18 solves)

I miss the good old Java days...

Author: Gianluca Altomani <@devgianlu>

## Overview

The challenge consist of a stripped Golang binary that implements a single `main` function. The flag is read from stdin
and checked against an internal state. The output reveals only whether the flag is correct or not.

The meaning of this challenge is to provide a very brief introduction to Golang's handling of reflection and its
internals for storing type information.

The input flag is transformed into a list of commands to navigate a 3D maze each represented by a struct:

```go
switch c & 3 {
    case 0:
        ops = append(ops, &Move{int((c >> 2) & 0b111), int(c >> 5)})
    case 1:
        ops = append(ops, &JumpUp{int(c >> 2)})
    case 2:
        ops = append(ops, &JumpDown{int(c >> 2)})
    case 3:
        ops = append(ops, &Teleport{int(c >> 2)})
}
```

Then the operations to navigate the virtual maze are performed starting from point (0, 0, 0) and checked at each 
iteration from a list of targets. If all iterations are performed correctly the program outputs `correct`.

## Solution

The core of the challenge is understanding how the following type switch maps each type to the correct action 
to perform on the maze:

```go
switch op := op.(type) {
    case *Move:
        ...
    case *JumpUp:
        ...
    case *JumpDown:
        ...
    case *Teleport:
        ...
}
```

Detailed information on how type switches work in Go can be found [here](https://github.com/teh-cmc/go-internals/blob/master/chapter2_interfaces/README.md#type-switches).

After extracting the maze from the binary, it is enough to reconstruct the flag by following each step.
If all three coordinates change, then it's a teleport, if only the first two change it's a move, 
else it's a jump up or down. See the code below for the actual implementation.

## Exploit

```py
targets = [
    (27, 27, 27), (31, 30, 27), (31, 30, 52), (31, 30, 25), (31, 30, 42), (15, 14, 58), (27, 26, 46), (11, 10, 62),
    (21, 20, 32), (21, 20, 8), (21, 20, -20), (21, 20, 6), (21, 20, -21), (12, 13, -14), (27, 26, -27), (27, 26, -51),
    (27, 26, -27), (3, 2, -3), (25, 24, -25), (14, 15, -16), (19, 18, -16), (21, 21, -16), (21, 21, 9), (2, 2, 30),
    (27, 27, 7), (0, 0, 28), (27, 27, 7), (28, 30, 7), (11, 9, 16), (16, 18, 11), (19, 21, 11), (20, 24, 11),
    (3, 15, 28), (3, 15, 2), (3, 15, 26), (3, 15, -3), (3, 15, 21), (20, 24, 2), (20, 24, -26), (20, 24, -1),
    (20, 24, -26), (23, 27, -26), (23, 27, -1), (15, 3, -25), (20, 6, -25), (20, 6, 1), (15, 29, 26), (15, 29, -1),
    (24, 10, -24), (20, 6, -28), (20, 6, -52), (26, 7, -52), (26, 7, -77), (27, 10, -77), (33, 11, -77), (57, 19, -85),
    (57, 19, -61), (57, 19, -30),
]

targets.insert(0, (0, 0, 0))

flag = []
for i, t in enumerate(targets[:-1]):
    nt = targets[i + 1]
    if t[0] != nt[0] and t[1] != nt[1] and t[2] != nt[2]:
        magic = t[0] ^ nt[0]
        assert magic == t[1] ^ nt[1]
        assert magic == t[2] ^ nt[2]

        flag += [(magic << 2) | 3]
    elif t[0] != nt[0] and t[1] != nt[1] and t[2] == nt[2]:
        x, y = nt[0] - t[0], nt[1] - t[1]
        flag += [(y << 5) | (x << 2) | 0]
    elif t[0] == nt[0] and t[1] == nt[1] and t[2] != nt[2]:
        if t[2] > nt[2]:
            times = t[2] - nt[2]
            flag += [(times << 2) | 2]
        else:
            times = nt[2] - t[2]
            flag += [(times << 2) | 1]
    else:
        assert False, f'{t} {nt}'

flag = bytes(flag).decode()
print(flag)
```

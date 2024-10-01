# openECSC 2024 - Final Round

## [rev] bend-ell (1 solve)

trees, leafs, folds and bends... I'm not getting much of it, at least they say it's fast!

Author: Andrea Raineri <@Rising>

## Overview

The challenge implements the Speck cipher in _Bend_ programming language. Bend language is oriented to parallelization, typically submitting operations to concurrent threads whenever possible. This parallelization principle is exploited in the implementatation in two ways:

1. encryptions are performed on single bytes of the flags (22 round speck) in parallel, by building at first a binary tree with each leaf containing the required parameters for the encryption (i.e. `pt1`, `pt2`, `k1`, `k2`)
2. bytes are transformed to binary trees of bits, all bitwise operations are performed using these tree-alike structures

## Solution

NOTE: Fundamental to be able to understand the HVM code is reading a bit the syntax declarations in [HVM2 paper](https://github.com/HigherOrderCO/HVM/blob/main/paper/HVM2%20-%20Extended%20Abstract.pdf).

We start our analysis from the `main` function. The output of the main function (i.e. the content of `output.txt`) comes from the `rd` variable, which is linked to the output of `main__fold0` function, called with `qd`. `qd` is the result of a long list of instruction that is building a large binary `Tree` with `Quadruple` as leafs containing some constants, the input of the algorithm (in this case, flag as `pt1`, `pt2` and the two keystrings `k1`, `k2`).

`f10` == `sum (+)`
`f0` == `sub (-)`
`f12` == `mod (%)`
`f13` == `div (/)`
`f14` == `xor (^)`
`f15` == `mul (*)`
`f9` == `rol`

`main__fold0`: from Bend's documentation we understand that `fold` is a specific operation of the language which allows to consume recursive datatypes (like `Tree`) and produce some output. The call is delegated to `main__fold0__C8`

`main__fold0__C8`: the `?()` symbol represents a switch operation. The function being executed depends on the type of `a`. Being `a` elements of a `Tree` being traversed, the two cases are `Tree/Node` and `Tree/Leaf`

`main__fold0__C6`: this function is calling again `main__fold0` on two subelements of the received argument. This function is descending the tree calling recursively on left and right nodes of the elements

`main__fold0__C7`: this function is called on `Tree/Leaf` elements of the tree. Following the call delegations, we reach `main__fold0__C4`

`main__fold0__C4`: this function seems to be receiving 4 parameters (i.e. the 4 elements of the `Quadruple`) and has as output the var `i`, which is connected to the result of `main__fold0__C3(f16(b, d, f, h))`. `b, d, f, h` are obtained as results of some pre-processing of function `f5` on `a, b, c, d`, elements of the `Quadruple`

`f5`: here we see references to the keyword `bend`, which is a specific instruction in the language to build recursive data structures. The function receives a number, contained in `a`. `f5__bend0` is directly called with `(16, a)` as args.

- `f5__bend0`: takes `a, b` as args and calls either `f5__bend0__C0` or `f5__bend0__C1` depending on the result of `a < 0x0000002`
- `f5__bend0__C0`: is building a `Tree/Node` with two `Tree/Leaf` children with values `f13(a, b)` and `f12(e, f)`. From Bend specifications we actually see that `{}` is a duplicator, meaning that actually `a == e, b == f (== a of f5)`.
- `f5__bend0__C1`: is recursively calling `f5__bend0` as `f5__bend0(arg1 / 2, arg2 >> (arg1 / 2))` and `f5__bend0(arg1 / 2, arg2 & ((1 << (arg1 / 2)) - 1))`

Analysing the full recursive algorithm we can see that `f5` is converting number to binary trees with their bit representation.

`f16`: we see the same `bend`-style pattern. The function is generating a recursive data structure. One path is followed for the condition `> 0x16 (22)` and one for the inverse condition. More interesting is the path `f16__bend0__C5`, which is the one being executed 22 times. Here the `f3` function is called with `f16` args contained inside a `Block` type, holding generically two elements.

`f3(v1, v2, v3)`: following the variable connections we can reconstruct the following function body

```python
def f3__C0(x1, x2, x3, x4, x5):
    x3_tree = f5(x3) -> to_binary_tree(x3)

    t1 = f6(
        tree_f12_f10(f7(x1, 8), x2),
        x5
    )

    t2 = f6(
        tree_f9(x2, 3),
        t1
    )

    t3 = f6(
        tree_f12_f10(f7(x4, 8), x5),
        x3_tree
    )

    t4 = f6(
        tree_f9(x5, 3),
        t3
    )

    return Pair(
        Block(t3, t4),
        Block(t1, t2)
    )
```

We can try to replace some already known functions, `f12, f10, f9`. By analyzing `f6` we also find out that it is simply performing a bitwise xor over the binary tree bit representation of the numbers, so we can call it `tree_xor`.

Now we get the following:

```python
def f3__C0(x1, x2, x3, x4, x5):
    x3_tree = to_binary_tree(x3)

    t1 = tree_xor(
        tree_mod_add(f7(x1, 8), x2),
        x5
    )

    t2 = tree_xor(
        tree_rol(x2, 3),
        t1
    )

    t3 = tree_xor(
        tree_mod_add(f7(x4, 8), x5),
        x3_tree
    )

    t4 = tree_xor(
        tree_rol(x5, 3),
        t3
    )

    return Pair(
        Block(t3, t4),
        Block(t1, t2)
    )
```

In this function we can spot some similarity with the Speck round function (assumption that matched with the function being called 22 times, a typical number of rounds for one the possible Speck implementations).

Leaving the reversing step of the remaining functions, which are utility functions to work with this particular binary tree structure for `ror` and conversion operations, we can solve the challenge by taking the output in attachments and the key in the source HVM and decrypt the flag.

## Exploit

```python
def ror(x, y):
    return (x >> y | x << (16 - y)) & 0xFFFF


def rol(x, y):
    return (x << y | x >> (16 - y)) & 0xFFFF


# speck round
def speck_round(x, y, k):
    x = ror(x, 8)
    x = (x + y) & 0xFFFF
    x = x ^ k
    y = rol(y, 3)
    y = y ^ x
    return x, y


def speck_inverse_round(x, y, k):
    y = y ^ x
    y = ror(y, 3)
    x = x ^ k
    x = (x - y) & 0xFFFF
    x = rol(x, 8)
    return x, y


def encrypt(k1, k2, x, y):
    for i in range(22):
        x, y = speck_round(x, y, k2)
        k1, k2 = speck_round(k1, k2, i)
    return k1, k2, x, y


def decrypt(k1, k2, x, y):
    round_keys = []
    for i in range(22):
        round_keys.append((k1, k2))
        k1, k2 = speck_round(k1, k2, i)

    for i in range(21, -1, -1):
        x, y = speck_inverse_round(x, y, round_keys[i][1])

    return x, y

with open('output.txt', 'r') as f:
    out = f.read()

import re

regex = r"Tree/Leaf/tag ([01])\)"
binary = re.findall(regex, out)
binary = ''.join(binary)

# split in 32 bits
binary = [binary[i:i+32] for i in range(0, len(binary), 32)]
# split each 32 in (16,16) tuples
cts = [(int(b[:16], 2), int(b[16:], 2)) for b in binary]

_k = [
    (43418 , 42714 , 28528 , 38463),
    (11853 , 55605 , 25966 , 48943),
    (7000 , 50060 , 17731 , 46359),
    (58534 , 56580 , 21315 , 28647),
    (3852 , 46811 , 31572 , 59416),
    (7280 , 61910 , 18505 , 20205),
    (31476 , 58745 , 21343 , 47889),
    (61439 , 52037 , 18771 , 429),
    (63343 , 22807 , 24385 , 50471),
    (17925 , 49889 , 24390 , 22568),
    (31528 , 13244 , 16715 , 55712),
    (3604 , 20559 , 17759 , 36772),
    (50138 , 35287 , 17996 , 31213),
    (27415 , 16291 , 16711 , 25633),
    (34707 , 59676 , 24404 , 19203),
    (22998 , 42645 , 18505 , 22976),
    (48192 , 12640 , 21343 , 40651),
    (62478 , 35294 , 18771 , 37626),
    (35745 , 59992 , 24385 , 58772),
    (8086 , 10425 , 24390 , 5505),
    (3361 , 64020 , 16715 , 45026),
    (43426 , 30243 , 17759 , 51598),
    (15093 , 871 , 17996 , 53717),
    (34351 , 15088 , 16711 , 17173),
    (40944 , 55415 , 24404 , 41794),
    (22105 , 47786 , 18505 , 37942),
    (45515 , 38617 , 21343 , 33708),
    (62634 , 60377 , 18771 , 44550),
    (44682 , 27639 , 24385 , 7312),
    (49040 , 33309 , 24390 , 46674),
    (59259 , 21129 , 16715 , 54674),
    (16724 , 43999 , 17789 , 21850)
]
key = [(k1, k2) for k1, k2, _, _ in _k]
pts = [decrypt(k1, k2, x, y) for (k1,k2),(x,y) in zip(key,cts)]
flag = b''.join([int.to_bytes(x, length=2, byteorder='big') for x, _ in pts]).decode()
print(flag)
```

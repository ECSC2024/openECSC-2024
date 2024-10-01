# openECSC 2024 - Final Round
## [rev] Hack the matrix (7 solves)

Wake up Neo, we need to hack the matrix.

```
nc matrix.challs.open.ecsc2024.it 47007
```

Author: Fabio Zoratti <@orsobruno96>

## Overview
The challenge is a standard x86_64 binary stripped. From the first inspection it is clear that this is a crackme. Besides the binary, there is a python script that calls it giving the user input as `argv[1]`.

The program checks `argv[1]` and checks that it is of the form `not_the_flag{stuff}` and checks that `stuff` is 16 bytes long.
After that, it uses each byte of the content of the flag to overwrite a byte of a floating point number inside some RW structures hardcoded in the program.

After this, it uses some of these structs in order to perform some computations and lastly it computes some kind of distance between the computed stuff and other global variables. If the distance is less than `1e-30`, the flag is correct and it is printed by the program.


## Solution path
Understanding what the program does requires a bit of reversing, but can be easily guessed using the name of the chall (hack the matrix). This program is performing some matrix multiplications (one of the matrix has the flag embedded) and then check if the result is close enough to a target matrix, with L2 norm.

There are 6 matrices in this program, all `4x4`, we will call them `A, B, C, D, E, F`, in order. `E` is the target matrix, while `F` is the matrix where the flag is embedded. The operation performed is

```
res = A . F . B . C . D
if (norm(res - E) < 1e-18) {
 puts("success")
}
```

In order to obtain the matrices from the binary we can use some SRE like ghidra and export the symbols. Done that, we can use pwntools

```python
from pwn import context, ELF, u64
from struct import pack, unpack
from pathlib import Path
from subprocess import check_output, CalledProcessError
import logging
import numpy as np


def load_matrix(address: int, rows: int, cols: int):
    mat = np.zeros((rows, cols), dtype="double")
    content = exe.read(address, 8*rows*cols)
    for i, chunk in enumerate(chunks(content, 8)):
        row, col = divmod(i, cols)
        mat[row, col] = unpack("<d", chunk)[0]
    return mat


def main():
    A = load_matrix(exe.sym['A'], 4, 4)
```

With all the matrices loaded, we can compute the wanted `F`,

```
targetF = A^-1 . E . (B . C . D)^-1
```

Done that, we can disembed the flag from the floating point numbers. To do so, we can understand that the code that embeds the chars in the numbers is something like

```c
uint64_t bitmask_magic(uint64_t oldval, uint64_t sub, size_t shift) {
  size_t realshift = 64 - shift - 8;
  uint64_t mask = 0xffll << realshift;
  return (oldval & ~mask) | (sub << realshift);
}
```

Inverting this operation is very simple in python


```python
def compute_flag(targetF, shifts: int):
    flag = []
    for i in range(4):
        for j in range(4):
            tval = targetF[i, j]
            intval = u64(pack("<d", tval))
            intval >>= (64 - 8 - shifts[4*i + j])
            intval &= 0xff
            flag.append(intval)
    flag = bytes(flag)
    return flag
```


We now only need to add the rest, `not_the_flag{content}` and the chall is solved. We can `nc` to the remote server and give this input and obtain the flag.


## Alternative solution
You can bruteforce one char at a time trying to minimize the norm. At each step, you explore all the possibilities for a single char and choose the char that has the least value for the norm.

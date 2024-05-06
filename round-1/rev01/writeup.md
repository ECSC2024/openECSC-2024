# openECSC 2024 - Round 1

## [rev] fsvm (175 solves)

I want this VM to generate a good description, but all I get is "no".

Author: Matteo Protopapa <@matpro>

## Overview

The challenge consists of two files: an ELF that implements a virtual machine and a binary file containing a bytecode. If we run the challenge with the command `./vm bytecode`, the progaram asks for a flag in stdin, and then it prints "no", unless we provide the correct flag. In this case, the program prints "ok".

## Solution

The VM implements few instructions, with the peculiarity that the "registers" are text files. Inspecting the bytecode, we can understand that it firstly builds and prints the string "flag:", then it reads from stdin. Afterwards, it repeatedly pops a character from the end of the input string, subtracts a number and concatenates the result in one of the registers. In parallel, it concatenates a 0 in another register. This process is repeated 29 times, then the program compares the two registers. If they are equal, then it prints "ok", otherwise it prints "no".

Therefore, the bytecode implements a function similar to the C's `strncmp`. We can recover the flag as the concatenation of the (reversed) list of numbers subtracted from the input string, converted to ASCII.

## Exploit

```python
print(''.join(chr(c) for c in [125, 100, 52, 99, 55, 56, 101, 52, 99, 109, 118, 121, 115, 97, 101, 114, 101, 112, 117, 115, 123, 67, 83, 67, 69, 110, 101, 112, 111][::-1]))
```

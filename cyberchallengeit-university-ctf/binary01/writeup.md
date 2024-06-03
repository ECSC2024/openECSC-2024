# CyberChallenge.IT 2024 - University CTF

## [binary] CCIA (106 solves)

We recovered this message from the CCIA (CyberChallenge.IT Intelligence Agency), but apparently only Agent X can read it. Can you crack it?

Author: Matteo Protopapa <@matpro>

## Overview

The challenge takes an input, checks it internally and, if it's correct, prints the flag. Decompiling the binary, we can see that the flag is checked as follows (as IDA decompiles it, v6 is an hardcoded array, while src is the user input):

```c
if ( v6[i] != (unsigned __int8)-src[i] )
```

## Solution

We can simply extract the array used to check the user input and recover the correct one, as it should be made of bytes that are the opposite of each hardcoded byte.

## Exploit

```python
#!/usr/bin/env python3

checkval = [189, 189, 183, 172, 133, 140, 152, 207, 141, 161, 147, 155, 141, 141, 159, 153, 205, 161, 137, 151, 148, 148, 161, 141, 155, 148, 154, 161, 155, 146, 157, 142, 135, 144, 201, 161, 151, 146, 161, 205, 161, 206, 161, 207, 161, 158, 157, 202, 199, 202, 204, 202, 206, 131]

key = []
for c in checkval:
    key.append(256-c)
key = bytes(key)

print(key)
```

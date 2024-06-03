# CyberChallenge.IT 2024 - University CTF

## [rev] License Checker (10 solves)

My license expired and I can't afford to renew it! Please buy me an activation code!

`nc licensechecker.challs.external.open.ecsc2024.it 38204`

The license server port for this challenge is:

`38205`

Author: Alberto Carboneri <@Alberto247>

## Overview

The challenge implements a simple license verification mechanism.

By launching the binary we are provided with the following message:
`Usage: REMOTE=<license-server-address> PORT=<license-server-port> ./licensechecker`

We can obtain those information from the challenge description. After substituting those in the above command we are finally greeted with a prompt:
`Your free trial has expired. Please provide your license key in order to keep using this software.`

Let's analyze the code with a disassembler like Ghidra to better understand the flow.
The provided binary is not stripped and consists of two user-defined functions, `main` and `connect_to_license_check_server`. The latter handles the connection to a remote server and returns the file descriptor of the newly created socket, so for the purpouse of the solution can be safely ignored. The `main` function is where all the application logic is handled.
It reads the input from the user, strips away any newline at the end, and then verifies its length to be a multiple of three and, for each triplet of characters, for some simple constraints to be respected.
Then it allocates two memory sections, one fixed at the address 0x60000 with read and write permissions, and one at a random address, with read, write and execute permissions.
After connecting to the license server the binary starts to iterate on every triplet of characters obtained from the user input. Specifically it implements the following logic in the for loop:

- Send the first character to the remote server
- Read a character from the remote server, save it as the variable `size`
- Read `size` characters from the remote server and save those in the RWX memory section
- Execute the RWX memory section with the other two user-provided characters as parameters.

Finally, the program takes the first 128 bytes of the memory allocated at 0x60000, calculates the crc32 of those values, and if the results corresponds to 0xbadc0ff3 provides the user with the flag.

## Solution

The first step towards the solution is understanding what is being received and executed from the license server.
We can write a small script replicating the challenge code to obtain it.
We can assume there are only 10 different possible responses from the server, as the values we are allowed to send to it are only numbers from 0 to 9.

```python
r = remote("licensechecker.challs.external.open.ecsc2024.it", 38205)
for x in range(10):
    r.send(str(x).encode())
    size=r.recv(1)
    data=r.recv(int.from_bytes(size, 'little'))
    print(data)
```

By disassembling the received data we can obtain the assembly codes:

```assembly
;code 0
   0:   48 8d 04 25 00 00 06 00         lea    rax, ds:0x60000
   8:   48 01 f8                add    rax, rdi
   b:   48 8b 18                mov    rbx, QWORD PTR [rax]
   e:   48 31 f3                xor    rbx, rsi
  11:   48 89 18                mov    QWORD PTR [rax], rbx
  14:   c3                      ret

;code 1
   0:   48 8d 04 25 00 00 06 00         lea    rax, ds:0x60000
   8:   48 01 f8                add    rax, rdi
   b:   48 83 c0 19             add    rax, 0x19
   f:   48 8b 18                mov    rbx, QWORD PTR [rax]
  12:   48 31 f3                xor    rbx, rsi
  15:   48 89 18                mov    QWORD PTR [rax], rbx
  18:   c3                      ret

;code2
   0:   48 8d 04 25 00 00 06 00         lea    rax, ds:0x60000
   8:   48 01 f8                add    rax, rdi
   b:   48 83 c0 32             add    rax, 0x32
   f:   48 8b 18                mov    rbx, QWORD PTR [rax]
  12:   48 31 f3                xor    rbx, rsi
  15:   48 89 18                mov    QWORD PTR [rax], rbx
  18:   c3                      ret

;code3
   0:   48 8d 04 25 00 00 06 00         lea    rax, ds:0x60000
   8:   48 01 f8                add    rax, rdi
   b:   48 83 c0 4b             add    rax, 0x4b
   f:   48 8b 18                mov    rbx, QWORD PTR [rax]
  12:   48 31 f3                xor    rbx, rsi
  15:   48 89 18                mov    QWORD PTR [rax], rbx
  18:   c3                      ret

;code4
   0:   48 8d 04 25 00 00 06 00         lea    rax, ds:0x60000
   8:   48 01 f8                add    rax, rdi
   b:   8a 18                   mov    bl, BYTE PTR [rax]
   d:   40 30 f3                xor    bl, sil
  10:   88 18                   mov    BYTE PTR [rax], bl
  12:   c3                      ret

;code5
   0:   48 8d 04 25 00 00 06 00         lea    rax, ds:0x60000
   8:   48 01 f8                add    rax, rdi
   b:   48 83 c0 19             add    rax, 0x19
   f:   8a 18                   mov    bl, BYTE PTR [rax]
  11:   40 30 f3                xor    bl, sil
  14:   88 18                   mov    BYTE PTR [rax], bl
  16:   c3                      ret

;code6
   0:   48 8d 04 25 00 00 06 00         lea    rax, ds:0x60000
   8:   48 01 f8                add    rax, rdi
   b:   48 83 c0 32             add    rax, 0x32
   f:   8a 18                   mov    bl, BYTE PTR [rax]
  11:   40 30 f3                xor    bl, sil
  14:   88 18                   mov    BYTE PTR [rax], bl
  16:   c3                      ret

;code7
   0:   48 8d 04 25 00 00 06 00         lea    rax, ds:0x60000
   8:   48 01 f8                add    rax, rdi
   b:   48 83 c0 4b             add    rax, 0x4b
   f:   8a 18                   mov    bl, BYTE PTR [rax]
  11:   40 30 f3                xor    bl, sil
  14:   88 18                   mov    BYTE PTR [rax], bl
  16:   c3                      ret

;code8
   0:   48 8d 04 25 00 00 06 00         lea    rax, ds:0x60000
   8:   48 c7 c3 00 00 00 00    mov    rbx, 0x0
   f:   48 83 fb 64             cmp    rbx, 0x64
  13:   7d 11                   jge    0x26
  15:   48 8b 0c 18             mov    rcx, QWORD PTR [rax+rbx*1]
  19:   48 f7 d1                not    rcx
  1c:   48 89 0c 18             mov    QWORD PTR [rax+rbx*1], rcx
  20:   48 83 c3 08             add    rbx, 0x8
  24:   eb e9                   jmp    0xf
  26:   c3                      ret

;code9
   0:   c3                      ret
```

Each code loads a pointer to the area mapped at 0x60000 and applies different operations to its contents.
Codes 0 to 3 xor a byte at the offset defined by parameter 1 plus a constant with the value defined by parameter 2.
Codes 4 to 7 do the same operation differently.
Code 8 negates 100 bytes at the address 0x60000.
And code 9 does nothing.

Our objective is to use the above codes to edit the memory in such a way that the final CRC calculation ends up being correct.

There are several ways to obtain a sequence of bytes with a known CRC. One of such techniques, albeit probably an over complicated one, is using z3.
After generating the sequence of bytes we can convert it to a sequence of characters which, when interpreted by the program, will modify the memory accordingly.
The exploit presented below generates a valid license, connects to the remote server and obtains the flag.

## Exploit

```python
#!/usr/bin/python
from z3 import *
from pwn import *

# crc32 implementation using z3 functions
def z3crc32(data, crc = 0):
    crc ^= 0xFFFFFFFF
    for c in data:
        for block in range(24, -1, -8):
            crc ^= LShR(c, block) & 0xFF
            for i in range(8):
                crc = If(crc & 1 == BitVecVal(1, 32), LShR(crc, 1) ^ 0xedb88320, LShR(crc, 1))
    return crc ^ 0xFFFFFFFF

s = Solver()

# data simulates the 128 bytes of memory at 0x60000
data = [BitVec('data'+str(i),32) for i in range(128//4)] 

# Returns a z3 expression that is true if the input BitVec32 is a 4-byte string is all uppercase letters. This checks from 0 to 25 as the program substracts 'A' from our input
def isAsciiUppercase(bv):
    # Note the use of z3.And here. Using python's `and` would be incorrect!
    return And(0 <= (LShR(bv,  0) & 0xff), (LShR(bv,  0) & 0xff) < 25,
               0 <= (LShR(bv,  8) & 0xff), (LShR(bv,  8) & 0xff) < 25,
               0 <= (LShR(bv, 16) & 0xff), (LShR(bv, 16) & 0xff) < 25,
               0 <= (LShR(bv, 24) & 0xff), (LShR(bv, 24) & 0xff) < 25)

# First 20 letters must be Ascii uppercase. This is not really needed but is used to keep things simple when generating the license
for d in data[:5]:
    s.add(isAsciiUppercase(d))

# Rest of the data is zero, as memory is initialized at 0
for d in data[5:]:
    s.add(d==0x0)

# Compute the crc32
crc = z3crc32(data)

# Add the constraint of the crc being 0xbadc0ff3
s.add(crc == 0xbadc0ff3)

# Check for satisfiability
s.check()
m = s.model()

# Extract the concrete values of the variables in the model
s = b''
for d in data:
    s += m.eval(d).as_long().to_bytes(4, 'big')

# Generate a license from the memory representation
code=""
for i, c in enumerate(s.rstrip(b"\x00")):
    code+="0"+chr(ord('A')+i)+chr(ord('A')+c)

# Connect to the remote and get the flag
r = remote("licensechecker.challs.external.open.ecsc2024.it", 38204)
r.recvuntil(b"> ")
r.sendline(code.encode())
r.recvuntil(b"Signed: ")
flag=r.recvline().strip().decode()
assert "CCIT{" in flag

print(flag)

r.close()
```

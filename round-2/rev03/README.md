# openECSC 2024 - Round 2

## [rev] Anti-rev (137 solves)

Good luck finding the secret word for my super secure program!

Author: Lorenzo Catoni <@lorenzcat>

## Solution

To make the reversing harder some instructions were injected into the binary, the purpose of these instructions is to confuse decompilers but behave like NOPs when executed, to not affect the program's behavoir. By looking at the disassembly it's easy to spot that the added instructions are the following (don't mind the offsets):
```asm
120f:       e8 00 00 00 00          callq  1214 <main+0x6b>
1214:       48 83 04 24 06          addq   $0x6,(%rsp)
1219:       c3                      retq
```

The call instruction is a call to the next instruction, so the only effect is to push rip to the stack, the add increments the saved rip by 6, which is the size of the add and ret instructions, and the ret instruction pops the saved rip from the stack and jumps to it, thus jumping to the next instruction. This way the added instructions are effectively NOPs, but the decompiler will fail to recognize that.

One way to get the decompiler to work is to patch these instructions with actual nops, this can be done in a very simple way with a python script like this:
```py
import sys

needle = b'\xe8\x00\x00\x00\x00\x48\x83\x04\x24\x06\xc3'
	
with open('anti-rev', 'rb') as f:
	obf = f.read()

deobf = obf.replace(needle, b'\x90' * len(needle))
with open('anti-rev-patched', 'wb') as f:
	f.write(deobf)
```

After this step decompilers work quite well and the source code of the main functioncan can be recovered, it is something like this:
```c

undefined8 main(void)

{
  long lVar1;
  bool correct;
  int iVar3;
  char *__s;
  char input [31];
  
  correct = false;
  fgets(input,0x1f,stdin);
  iVar3 = strncmp(input,"openECSC{",9);
  if (((iVar3 == 0) && (input[29] == '}')) &&
   /* ... 20 linear (affine) equations of input */) {
    correct = true;
  }
  if (correct) {
    __s = "Correct!";
  }
  else {
    __s = "Wrong!";
  }
  puts(__s);
}
```

The correct input can be found by solving the affine system or by putting the constraints into a sat solver, like in [solution.py](./solution.py).

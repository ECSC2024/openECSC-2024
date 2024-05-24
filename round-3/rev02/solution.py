"""
Fist part, disassemble the program
==================================
"""

import sys

# (mnemonic, number_of_args, has_immediate)
opcodes = [
  ("HALT", 0, False),
  ("LOAD", 1, True),
  ("LOAD_PTR", 1, False),
  ("STORE", 2, False),
  ("CMP_LT", 2, False),
  ("ADD", 2, False),
  ("SUB", 2, False),
  ("CALL", 0, True),
  ("RET", 0, False),
  ("JMP", 0, True),
  ("JZ", 1, True),
  ("JNZ", 1, True),
  ("PUSH", 1, False),
  ("POP", 1, False),
  ("AND", 2, False),
  ("NOT", 2, False),
]

with open(sys.argv[1], "rb") as f:
  prog = f.read()

args = ["A", "B", "C", "SP"]

i = 0
lines: dict[int, str] = {}
call_targets: set[int] = set()
while i < len(prog):
  op = prog[i]
  opcode = (op >> 4) & 0xF
  arg1 = (op >> 2) & 0x3
  arg2 = op & 0x3

  mnem, nargs, has_imm = opcodes[opcode]
  line = f"{i:04x}: {mnem}"
  line += "".join(f' {args[a]}' for a in [arg1, arg2][:nargs])
  line += f' {prog[i+1:i+3].hex() if has_imm else ""}'
  lines[i] = line

  if mnem == "CALL":
    call_targets.add(int.from_bytes(prog[i + 1 : i + 3], "big"))

  i += 3 if has_imm else 1

disass: list[str] = []
for addr, line in lines.items():
  if addr in call_targets:
    disass.append(f"func_{addr:04x}:")
  disass.append(line)

# print("\n".join(disass))

"""
Second part, find input solution  
==================================

it's split in two parts because during the solve it makes sense 
to write the disassemler first, then the solver
"""

"""
The "encoded" flag is modified by a series of expressions like so:

001b: LOAD A 0009
001e: LOAD_PTR A
001f: LOAD B 0007
0022: LOAD_PTR B
0023: ADD A B
0024: LOAD B 000f
0027: LOAD_PTR B
0028: CALL 0004
002b: LOAD B 000b
002e: LOAD_PTR B
002f: ADD A B
0030: LOAD B bb78
0033: ADD A B
0034: LOAD B 0008
0037: LOAD_PTR B
0038: CALL 0004
003b: LOAD B 0008
003e: STORE B A

it is computing the following pseudo code (operations are always from left to right):
f[8] ^= f[9] + f[7] ^ f[0xf] + f[0xb] + 0xbb78; f[8] &= 0xffFF;

or in general:
f[i] op_i= f[j0] op_j0 f[j1] op_j1 f[j2] op_j2 f[j3] op_j3 k; f[i] &= 0xffFF;

we observe that we can reverse the operations starting from the last one and going backwards:
f'[i] = f[i] op_i (f[j0] op_j0 f[j1] op_j1 f[j2] op_j2 f[j3] op_j3 k);
f[i] = f'[i] op_i_inv (f[j0] op_j0 f[j1] op_j1 f[j2] op_j2 f[j3] op_j3 k);

in the end it just iterates over all f[i] and compares them to the expected hardcoded values:
026f: LOAD A 0000
0272: LOAD_PTR A
0273: LOAD B c76e
0276: SUB A B
0277: JNZ A 0325
"""

from dataclasses import dataclass
import sys
from typing import Callable


@dataclass
class Op:
  f: Callable
  f_inv: Callable

Add = Op(f=lambda a, b: (a + b) & 0xffFF, f_inv=lambda a, b: (a - b) & 0xffFF)
Xor = Op(f=lambda a, b: a ^ b, f_inv=lambda a, b: a ^ b)


@dataclass
class Expression:
  i: int
  op_i: Op
  js: list[int]
  op_js: list[Op]
  k: int

  def backward(self, f: list[int]):
    j0, *js = self.js
    *op_js, op_jm1 = self.op_js

    a = f[j0]
    for ji, op_ji in zip(js, op_js):
      a = op_ji.f(a, f[ji])
    a = op_jm1.f(a, self.k)

    f[self.i] = self.op_i.f_inv(f[self.i], a)


idx_from_asm = lambda a: int(a.split(" ")[-1], 16)
op_from_asm = lambda a: Add if "ADD" in a else Xor
F_SIZE = 16


asm_iter = iter(disass)

expressions: list[Expression] = []

# skip until actual func
while not next(asm_iter).startswith("func_001b:"):
  pass

# parse expressions
for _ in range(F_SIZE):
  js: list[int] = []
  op_js: list[Op] = []

  j0 = idx_from_asm(next(asm_iter))
  next(asm_iter)  # LOAD_PTR
  js.append(j0)

  for _ in range(3):
    ji = idx_from_asm(next(asm_iter))
    next(asm_iter)
    js.append(ji)

    op_ji = op_from_asm(next(asm_iter))
    op_js.append(op_ji)

  k = idx_from_asm(next(asm_iter))
  op_jm1 = op_from_asm(next(asm_iter))
  op_js.append(op_jm1)

  i = idx_from_asm(next(asm_iter))
  next(asm_iter)  # LOAD_PTR
  op_i = op_from_asm(next(asm_iter))
  next(asm_iter)
  assert "STORE B A" in next(asm_iter)

  expressions.append(Expression(i=i, op_i=op_i, js=js, op_js=op_js, k=k))

# parse final state of f[...]
f: list[int] = [None] * F_SIZE
for _ in range(F_SIZE):
  i = idx_from_asm(next(asm_iter))
  next(asm_iter)  # LOAD_PTR
  f_i = idx_from_asm(next(asm_iter))
  next(asm_iter)  # SUB
  assert "JNZ" in next(asm_iter)  # JNZ

  f[i] = f_i

assert None not in f

# now evaluate expressions in reverse order
for e in reversed(expressions):
  e.backward(f)

flag = bytes.fromhex("".join(int.to_bytes(x, 2, "little").hex() for x in f))
print(flag.decode())
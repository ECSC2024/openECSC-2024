#!/usr/bin/env python3
import hashlib
import hmac
import os
import stat
import subprocess
import sys
import zipfile

# This is a sample script for generating static challenges (no remote) with different flags.
# This script is called by an automated tool. It must accept a single argument of the user id and
# output the flag generated for that user. Additionally, it must generate the challenge for this flag (and user)
# and write it to 'attachments/<attachment_name>/<userid>'. This script is run from the challenge root.

userid = sys.argv[1]
output_file = f"attachments/revrev.zip/{userid}"

import operator
import random
from dataclasses import dataclass
from functools import partial
from typing import Callable, Mapping, Sequence

import vm


@dataclass(frozen=True)
class Expression_op:
    name: str
    execute: Callable
    sym: str
    vm_op: vm.Op


expression_ops = [
    Expression_op("add", operator.add, "+", vm.ADD),
    Expression_op("xor", operator.xor, "^", lambda *_: vm.CALL(vm.Label("xor"))),
]


@dataclass
class Expression:
    """Represent expression in the form:
        `f[i] op= f[j0] op f[j1] op ... op x; f[i] &= 0xffFF;`

    where f[i] is a flag word (2 bytes), op is + or ^ and x is a constant 16-bit value.
    op order is always from left to right
    """

    i: int
    js: list[int]
    opi: Expression_op
    ops: list[Expression_op]
    const: int

    @classmethod
    def random(cls, *, i: int, js: Sequence[int], w: int, rnd: random.Random):
        return cls(
            i=i,
            js=rnd.sample(js, k=w),
            opi=rnd.choice(expression_ops),
            ops=rnd.choices(expression_ops, k=w),
            const=rnd.getrandbits(16),
        )

    def __str__(self):
        rv = f"f[{self.i}] {self.opi.sym}= "
        rv += " ".join(
            f"f[{j}] {op.sym}" for j, op in zip(self.js, self.ops, strict=True)
        )
        rv += f" {self.const}; f[{self.i}] &= 0xffFF;"

        return rv

    def evaluate_on(self, f: list[int]):
        """in place evaluation of the expression (modifies f)"""
        j0, *js = self.js
        *ops, op_m1 = self.ops

        rv = f[j0]
        for j, op in zip(js, ops, strict=True):
            rv = op.execute(rv, f[j])
        rv = op_m1.execute(rv, self.const)
        f[self.i] = self.opi.execute(f[self.i], rv) & 0xFFFF

    def to_asm(self, idx_to_addr: Mapping[int, int]) -> vm.Asm:
        j0, *js = self.js
        *ops, op_m1 = self.ops

        asm = vm.Asm()
        asm.add_op(vm.LOAD(vm.Reg.A, idx_to_addr[j0]))
        asm.add_op(vm.LOAD_PTR(vm.Reg.A, vm.Reg.A))
        for j, op in zip(js, ops, strict=True):
            asm.add_ops(
                vm.LOAD(vm.Reg.B, idx_to_addr[j]),
                vm.LOAD_PTR(vm.Reg.B, vm.Reg.B),
                op.vm_op(vm.Reg.A, vm.Reg.B),
            )
        asm.add_ops(
            vm.LOAD(vm.Reg.B, self.const),
            op_m1.vm_op(vm.Reg.A, vm.Reg.B),
            vm.LOAD(vm.Reg.B, idx_to_addr[self.i]),
            vm.LOAD_PTR(vm.Reg.B, vm.Reg.B),
            self.opi.vm_op(vm.Reg.A, vm.Reg.B),
            vm.LOAD(vm.Reg.B, idx_to_addr[self.i]),
            vm.STORE(vm.Reg.B, vm.Reg.A),
        )

        return asm


HKEY = b"\xf8BJ\x10]\xe6r9+\xaf\xdf\xce\xfc\x00\xa1."
random_part = hmac.new(HKEY, userid.encode(), hashlib.sha256).hexdigest()[:8]
FLAG_INNER = f"a_rev_inside_a_rev_ins..{random_part}"
FLAG = f"openECSC{{{FLAG_INNER}}}"


def main():
    flag_inn = FLAG_INNER.encode()
    flag_inn = [int.from_bytes(flag_inn[i : i + 2], "little") for i in range(0, len(flag_inn), 2)]
    idx_range = range(len(flag_inn))
    rand = random.Random(0x7a6a6b2f95d1734878c01264cd575d70)
    vars_ex = 4  # variables per expression

    chall = vm.Asm()
    chall.add_ops(vm.CALL(vm.Label("main")), vm.HALT())
    chall += vm.func_xor
    chall.add_op(vm.Label("main"))

    for i in rand.sample(idx_range, k=len(flag_inn)):
        js = [j for j in idx_range if j != i]
        e = Expression.random(i=i, js=js, w=vars_ex, rnd=rand)
        chall += e.to_asm(idx_range)
        e.evaluate_on(flag_inn)
        # print(e)

    # print(flag)

    for idx in idx_range:
        chall.add_ops(
            vm.LOAD(vm.Reg.A, idx),
            vm.LOAD_PTR(vm.Reg.A, vm.Reg.A),
            vm.LOAD(vm.Reg.B, flag_inn[idx]),
            vm.SUB(vm.Reg.A, vm.Reg.B),
            vm.JNZ(vm.Reg.A, vm.Label("end_wrong")),
        )

    chall.add_ops(
        vm.LOAD(vm.Reg.A, 1),
        vm.JMP(vm.Label("end_correct")),
        vm.Label("end_wrong"),
        vm.LOAD(vm.Reg.A, 0),
        vm.Label("end_correct"),
        vm.RET(),
    )

    test_file = f'/tmp/{os.urandom(4).hex()}'
    binary = './src/vm'
    with open(test_file, "wb") as f:
        f.write(chall.to_bytes())

    # with open("flag.as", "w") as f:
    #     f.write(str(chall))
    
    # *very* rudimentary correctness test
    os.chmod(binary, os.stat(test_file).st_mode | stat.S_IEXEC) # chmod +x

    flag = FLAG.encode()
    output = subprocess.check_output([binary, test_file], input=flag, stderr=subprocess.STDOUT)
    assert output == b'Correct!\n'

    wrong_flag = flag.replace(bytes((flag[-3],)), b'x')
    output = subprocess.check_output([binary, test_file], input=wrong_flag, stderr=subprocess.STDOUT)
    assert output == b'Wrong!\n'

    with zipfile.ZipFile(output_file, mode='w', compression=zipfile.ZIP_DEFLATED) as zf:
        zf.write(binary, "rev0")
        zf.write(test_file, "rev1")

    os.remove(test_file)

    print(FLAG)


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
from os import urandom
from pathlib import Path
from random import seed, choice, randint, shuffle
from shutil import copyfile
from subprocess import run, DEVNULL
from sys import argv

from pwn import process, u64, p64, logging

logging.disable()

from common import Operation, Opcode, rol, ror, sbitmask

SCRATCH_REGISTERS = [
    "rbx", "rcx", "r9", "r10", "r11", "r14", "r15",
]

DIR = Path(__file__).parent
FLAG_LEN = 0x30


def get_operations():
    ops = [
        Operation(
            choice([opc for opc in Opcode]),
            i,
            randint(0, 256),
        )
        for i in range(0x27)
    ]
    shuffle(ops)
    return ops


def fill_register_with_value(reg: str, val: int):
    ret = f"xor {reg}, {reg}" + "\n"
    values = []
    for _ in range(randint(0, 5)):
        tmp = randint(0, min(val, 1 << 16))
        values.append(tmp)
        val -= tmp
    ret = f"""
    mov {reg}, {val:#x}
    """ + "\n".join(f"    add {reg}, {v:#x}" for v in values)
    return ret


def generate_random_instruction(avoidreg):
    avail = set(SCRATCH_REGISTERS)
    avail.remove(avoidreg)
    reg1 = choice(list(avail))
    avail.remove(reg1)
    reg2 = choice(list(avail))
    imm = randint(0, 1 << 16)

    return "    " + choice([
        "mov {reg1}, {reg2}",
        "mov {reg1}, {imm:#x}",
        "add {reg1}, {reg2}",
        "add {reg1}, {imm:#x}",
        "sub {reg1}, {reg2}",
        "sub {reg1}, {imm:#x}",
        "push {reg1}\n    pop {reg2}",
        "nop",
    ]).format(reg1=reg1, reg2=reg2, imm=imm)


def operation_to_x86(op: Operation):
    addr = (op.offset) | (sbitmask(op.operand, 0, 16) << 16) | (randint(0, 1 << 16) << 24)
    opcode = randint(0, 1 << 23) | int(op.opcode) << 23 | (randint(0, 1 << 32) << 31)
    scratchreg = choice(SCRATCH_REGISTERS)

    raxfill = randomize_instruction(fill_register_with_value("rax", opcode), scratchreg)
    rdifill = randomize_instruction(fill_register_with_value("rdi", addr), scratchreg)
    rdxfill = randomize_instruction(fill_register_with_value("rdx", op.operand), scratchreg)
    if op.opcode in [Opcode.Add, Opcode.Xor]:
        return randomize_instruction(f"""
        {raxfill}
        mov {scratchreg}, {addr:#x}
        mov qword ptr [{scratchreg}], {randint(0, 1 << 16):#x}
        """, scratchreg)
    if op.opcode in [Opcode.Sub, Opcode.Rol, Opcode.Ror]:
        return randomize_instruction(f"""
        {rdifill}
        {raxfill}
        int3
        """, scratchreg)
    if op.opcode in [Opcode.AddQword]:
        return randomize_instruction(f"""
        {rdifill}
        {rdxfill}
        {raxfill}
        xor r12, r12
        div r12
        """, scratchreg)
    if op.opcode in [Opcode.SubQword]:
        return randomize_instruction(f"""
        {rdifill}
        {rdxfill}
        {raxfill}
        ud2
        """, scratchreg)

    raise ValueError(f"Invalid opcode {op.opcode}")


def randomize_instruction(x86_asm: str, scratchreg: str):
    modified = x86_asm.strip().split("\n")
    retval = []
    for inst in modified:
        retval += [generate_random_instruction(scratchreg) for _ in range(randint(0, 5))]
        retval += [inst]
    return "\n".join(retval)


def gen_custom_prompt():
    return "4lw4ys_f0ll0w_th3_s1gn4ls_" + urandom(10).hex()


def gen_scrambler(prompt: str):
    scrambler_content = """
    .intel_syntax noprefix

    .global scrambler
scrambler:
    push rax
    push rbx
    push rdi
    push rsi
    push r12
    push r13
    push r14
    push r15

    mov r8, rdi
    """

    for op in OPERATIONS:
        scrambler_content += operation_to_x86(op) + "\n"

    scrambler_content += """

    pop r15
    pop r14
    pop r13
    pop r12
    pop rsi
    pop rdi
    pop rbx
    pop rax

    ret
    """
    with open(str(DIR / "scrambler.S"), "w") as outfile:
        outfile.write(scrambler_content)
    run(["make", "scrambler.o"], check=True, cwd=str(DIR), stdout=DEVNULL, stderr=DEVNULL)


def bytes_to_c_string(val: bytes):
    return ", ".join([f"{c:#02x}" for c in val])


def compute_target(prompt: str):
    ret = [c for c in prompt.encode()]
    for op in OPERATIONS:
        if op.opcode == Opcode.Add:
            ret[op.offset] = (ret[op.offset] + op.operand) % 256
            continue
        if op.opcode == Opcode.Xor:
            ret[op.offset] ^= op.operand
            continue
        if op.opcode == Opcode.Sub:
            ret[op.offset] = (ret[op.offset] - op.operand) % 256
            continue
        if op.opcode == Opcode.Rol:
            ret[op.offset] = rol(ret[op.offset], op.operand, 8)
            continue
        if op.opcode == Opcode.Ror:
            ret[op.offset] = ror(ret[op.offset], op.operand, 8)
            continue
        if op.opcode == Opcode.AddQword:
            ret[op.offset:op.offset + 8] = p64((u64(bytes(ret[op.offset:op.offset + 8])) + op.operand) % (1 << 64))
            continue
        if op.opcode == Opcode.SubQword:
            ret[op.offset:op.offset + 8] = p64((u64(bytes(ret[op.offset:op.offset + 8])) - op.operand) % (1 << 64))
            continue
        raise ValueError(f"Invalid opcode {op.opcode}")
    return ret


def gen_obfuscated(target):
    content = f"""
u8 target[] = {{ {bytes_to_c_string(target)} }};
    """
    with open(str(DIR / "data.c"), "w") as outfile:
        outfile.write(content)
    run(["make", "cop"], check=True, cwd=str(DIR), stdout=DEVNULL, stderr=DEVNULL)


def check_valid(flag):
    with process([str(DIR / "cop")]) as io:
        io.sendline(flag.encode())
        io.recvuntil(b"clown license")
        io.recvline()
        content = io.recvline()
        return b"Nope" not in content


def main():
    userid = argv[1]
    run(["make", "clean"], check=True, cwd=str(DIR), stdout=DEVNULL, stderr=DEVNULL)
    prompt = gen_custom_prompt()
    gen_scrambler(prompt)
    target = compute_target(prompt)
    flag = f"openECSC{{{prompt}}}"
    gen_obfuscated(target)
    if check_valid(prompt):
        copyfile(str(DIR / "cop"), str(DIR.parent / "attachments" / "cop" / userid))
        print(flag)
    else:
        main()


if __name__ == '__main__':
    seed(0xdeadd0d0)
    OPERATIONS = get_operations()
    # print(*OPERATIONS, sep="\n")
    main()

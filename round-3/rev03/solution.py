#!/usr/bin/env python3
from pwn import context, ELF, u64, p64
from re import search
from unicorn import Uc, x86_const, UC_ARCH_X86, UC_MODE_64
from pathlib import Path

from src.common import Opcode, Operation, rol, ror, sbitmask

exe = context.binary = ELF(Path(__file__).parent / "src" / "cop.dbg")
target = exe.read(exe.sym['target'], 0x30)


ENDERS = ["int3", "mov    QWORD PTR", "div    r12", "ud2"]


def invert_target(operations: list[Operation]):
    ret = [i for i in target]
    for op in operations[::-1]:
        if op.opcode == Opcode.Add:
            ret[op.offset] = (ret[op.offset] - op.operand) % 256
            continue
        if op.opcode == Opcode.Xor:
            ret[op.offset] ^= op.operand
            continue
        if op.opcode == Opcode.Sub:
            ret[op.offset] = (ret[op.offset] + op.operand) % 256
            continue
        if op.opcode == Opcode.Rol:
            ret[op.offset] = ror(ret[op.offset], op.operand, 8)
            continue
        if op.opcode == Opcode.Ror:
            ret[op.offset] = rol(ret[op.offset], op.operand, 8)
            continue
        if op.opcode == Opcode.AddQword:
            ret[op.offset:op.offset + 8] = p64((u64(bytes(ret[op.offset:op.offset + 8])) - op.operand) % (1 << 64))
            continue
        if op.opcode == Opcode.SubQword:
            ret[op.offset:op.offset + 8] = p64((u64(bytes(ret[op.offset:op.offset + 8])) + op.operand) % (1 << 64))
            continue
        raise ValueError(f"Invalid opcode {op.opcode}")
    return bytes(ret).decode().replace("\x00", "")


def get_splitted_instructions():
    instructions = exe.disasm(
        exe.sym['scrambler'], 15000,
    )
    sequence = []
    accumulator = []

    for line in instructions.split("\n"):
        accumulator.append(line)
        for val in ENDERS:
            if val in line:
                sequence.append(accumulator)
                accumulator = []
                break
        if "ret" in line:
            break
    else:
        raise ValueError("Need to disassemble more")
    return sequence


def reg_to_args(val1: int, val2: int, opcode: Opcode):
    offset = sbitmask(val1, 0, 16)
    if opcode in [Opcode.AddQword, Opcode.SubQword]:
        operand = val2
    else:
        operand = sbitmask(val1, 16, 24)
    return offset, operand


def x86_to_opcode(instset: list[str]):
    emu = Uc(UC_ARCH_X86, UC_MODE_64)
    start_addr = int(instset[0].split(":")[0], 16)
    end_addr = int(instset[-1].split(":")[0], 16)
    bytecode = exe.read(start_addr, end_addr - start_addr)

    START = 0x4000
    STACK = 0x100000
    emu.mem_map(START, 0x1000)
    emu.mem_map(STACK, 0x200000)
    emu.mem_write(START, bytecode)
    emu.reg_write(x86_const.UC_X86_REG_RSP, STACK + 0x5000)
    emu.emu_start(START, START + end_addr - start_addr)
    rax = emu.reg_read(x86_const.UC_X86_REG_RAX)
    opcode = Opcode(sbitmask(rax, 23, 31))

    if "int3" in instset[-1]:
        reg1 = emu.reg_read(x86_const.UC_X86_REG_RDI)
        reg2 = 0
    elif "QWORD PTR" in instset[-1]:
        regname = search(r"QWORD PTR \[([a-z0-9A-Z]+)\]", instset[-1]).group(1)
        reg1 = emu.reg_read(getattr(x86_const, f"UC_X86_REG_{regname.upper()}"))
        reg2 = 0
    elif "div    r12" in instset[-1]:
        reg1 = emu.reg_read(x86_const.UC_X86_REG_RDI)
        reg2 = emu.reg_read(x86_const.UC_X86_REG_RDX)
    elif "ud2" in instset[-1]:
        reg1 = emu.reg_read(x86_const.UC_X86_REG_RDI)
        reg2 = emu.reg_read(x86_const.UC_X86_REG_RDX)
    else:
        raise ValueError(f"Invalid instset: {instset}")
    offset, operand = reg_to_args(reg1, reg2, opcode)
    return Operation(opcode, offset, operand)


def main():
    sequence = get_splitted_instructions()
    instructions = [
        x86_to_opcode(inst) for inst in sequence
    ]
    # print(*instructions, sep="\n")
    flag = invert_target(instructions)
    print(f"flag{{{flag}}}")


if __name__ == '__main__':
    main()

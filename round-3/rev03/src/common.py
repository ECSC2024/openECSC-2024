from enum import IntEnum
from collections import namedtuple


Operation = namedtuple("Operation", ["opcode", "offset", "operand"])


class Opcode(IntEnum):
    Add = 0x56
    Xor = 0x71
    Sub = 0x90
    Rol = 0x13
    Ror = 0x21
    AddQword = 0x34
    SubQword = 0x98


def rol(val, r_bits, max_bits):
    return (val << r_bits % max_bits) & (2**max_bits - 1) | \
        ((val & (2**max_bits-1)) >> (max_bits-(r_bits % max_bits)))


def ror(val, r_bits, max_bits):
    return ((val & (2**max_bits-1)) >> r_bits % max_bits) | \
        (val << (max_bits-(r_bits % max_bits)) & (2**max_bits-1))


def bitmask(val, low, hi):
    return (val & (((1 << hi) - 1) ^ ((1 << low) - 1)))


def sbitmask(val, low, hi):
    return bitmask(val, low, hi) >> low

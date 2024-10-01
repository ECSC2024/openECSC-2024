#!/usr/bin/env python3
from pwn import context, ELF, u64
from struct import pack, unpack
from pathlib import Path
from subprocess import check_output, CalledProcessError
import logging
import numpy as np

logging.disable()


BASE_DIR = Path(__file__).parent
CHALL_FNAME = "matrix"
exe = context.binary = ELF(f"{BASE_DIR}/src/{CHALL_FNAME}")


def chunks(lst, n):
    """Yield successive n-sized chunks from lst."""
    for i in range(0, len(lst), n):
        yield lst[i:i + n]


def load_matrix(address: int, rows: int, cols: int):
    mat = np.zeros((rows, cols), dtype="double")
    content = exe.read(address, 8*rows*cols)
    for i, chunk in enumerate(chunks(content, 8)):
        row, col = divmod(i, cols)
        mat[row, col] = unpack("<d", chunk)[0]
    return mat


def load_arr(address: int, size: int):
    ret = []
    for chunk in chunks(exe.read(address, size*8), 8):
        ret.append(u64(chunk))
    return ret


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


def main():
    A = load_matrix(exe.sym['A'], 4, 4)
    B = load_matrix(exe.sym['B'], 4, 4)
    C = load_matrix(exe.sym['C'], 4, 4)
    D = load_matrix(exe.sym['D'], 4, 4)
    E = load_matrix(exe.sym['E'], 4, 4)
    # F = load_matrix(exe.sym['F'], 4, 4)
    shifts = load_arr(exe.sym['shifts'], 16)

    targetF = np.linalg.inv(A) @ E @ np.linalg.inv(B @ C @ D)
    flag = compute_flag(targetF, shifts)
    flag = f"not_the_flag{{{flag.decode()}}}"
    print(flag)
    try:
        check_output([exe.path, flag], cwd=BASE_DIR)
    except CalledProcessError as exc:
        raise ValueError(f"Computed flag is not valid: {flag}") from exc


if __name__ == '__main__':
    main()

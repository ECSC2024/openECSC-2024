#!/usr/bin/env python3
from pwn import ELF, context, flat, xor, p64
from argparse import ArgumentParser


def main():
    parser = ArgumentParser()
    parser.add_argument("--input", type=str, required=True)
    parser.add_argument("--output", type=str, required=True)

    args = parser.parse_args()
    exe = context.binary = ELF(args.input)

    # content = exe.section(".text")

    content = {}
    for segment in exe.segments:
        if segment.header["p_type"] != "PT_LOAD":
            continue
        if segment.header["p_flags"] != 5:
            continue
        # content[segment.header["p_vaddr"]] = segment.data()
        content = segment.data()

    # content = flat(content)
    off = (exe.vaddr_to_offset(exe.sym['main']) % 0x1000) + 0x100
    print(content[:off].hex(), content[off:].hex(), xor(content[off:], p64(0xdeadbeefdeadd0d0)).hex(), sep="\n\n\n")
    content = content[:off] + xor(content[off:], p64(0xdeadbeefdeadd0d0))

    print("offset", hex(exe.vaddr_to_offset(exe.sym['main'])))

    with open(args.output, "wb") as outfile:
        outfile.write(content)


if __name__ == '__main__':
    main()

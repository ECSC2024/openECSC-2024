#!/usr/bin/env python3

BROKEN = bytes([0xe8, 0x06, 0x00, 0x00, 0x00, 0x48, 0x83, 0x04, 0x24, 0x08, 0xc3, 0xeb, 0xf8])


def main():
    with open("../src/forgot", "rb") as infile:
        content = infile.read()
    content = content.replace(BROKEN, b"\x90"*len(BROKEN))
    with open("./forgot_patched", "wb") as outfile:
        outfile.write(content)


if __name__ == '__main__':
    main()

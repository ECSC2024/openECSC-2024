#!/usr/bin/env python3
import os
import re
import subprocess
import sys
import tempfile

userid = sys.argv[1]
flag_base = 'openECSC{oH_my_p4ra7l3l_w0rlds_aR3_f0ld1ng_and_b3nd1ng_%s}'
redacted_flag = 'openECSC{THIS_IS_A_FAKE_FLAG_THIS_IS_A_FAKE_FLAG_THIS_IS_A_FAKE}'


def gen_custom_flag() -> str:
    return flag_base % os.urandom(4).hex()


FLAG_LEN = 64

key1 = os.urandom(FLAG_LEN)
key2 = os.urandom(FLAG_LEN)
flag = gen_custom_flag()


def treefy(data):
    if len(data) == 1:
        return f"!Quadruple{str(data[0])}"
    else:
        # split into binary tree
        mid = len(data) // 2
        left = treefy(data[:mid])
        right = treefy(data[mid:])
        return f"![{left}, {right}]"


def to_16bit(data):
    return [int.from_bytes(data[i:i + 2], "big") for i in range(0, len(data), 2)]


def gen_attachment(userid: str):
    with open('src/main.bend', 'r') as cf:
        main_code = cf.read()

    # Find all functions
    pattern = r'(?<=def\s)(\w+)'
    function_names = set(re.findall(pattern, main_code))
    function_names.remove('main')
    function_names.remove('Block')
    function_names.remove('Pair')
    # Strip functions
    for i, function_name in enumerate(function_names):
        main_code = main_code.replace(f"{function_name}", f"f{i}")

    # Replace TREE_INPUT with generated tree input
    data = list(zip(
        to_16bit(key1),
        to_16bit(key2),
        to_16bit(flag.encode()),
        to_16bit(os.urandom(FLAG_LEN))
    ))
    tree_input = treefy(data)
    data_redacted = list(zip(
        to_16bit(key1),
        to_16bit(key2),
        to_16bit(redacted_flag.encode()),
        to_16bit(os.urandom(FLAG_LEN))
    ))
    tree_input_redacted = treefy(data_redacted)  # same key, different flag and nonce (plaintext)
    main_code_redacted = main_code.replace("TREE_INPUT", tree_input_redacted)
    main_code = main_code.replace("TREE_INPUT", tree_input)

    with tempfile.TemporaryDirectory() as cwd:
        with tempfile.NamedTemporaryFile(mode='w') as cf:
            cf.write(main_code)
            cf.flush()

            out = subprocess.run(['bend', 'run', cf.name], capture_output=True, text=True, cwd=cwd)
            assert len(out.stdout) > 0
            with open(f'attachments/output.txt/{userid}', 'w') as of:
                of.write(out.stdout)

        with tempfile.NamedTemporaryFile(mode='w') as cf:
            cf.write(main_code_redacted)
            cf.flush()

            code = subprocess.run(['bend', 'gen-hvm', cf.name], capture_output=True, text=True, cwd=cwd)
            assert len(code.stdout) > 0
            with open(f'attachments/chall.hvm/{userid}', 'w') as of:
                of.write(code.stdout)


gen_attachment(userid)
print(flag)

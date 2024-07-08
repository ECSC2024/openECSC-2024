import json, struct, string, base64

arch = "64"  # "32"
pointer_size = "Q" if arch == "64" else "I"


with open("ssh.exe.maxidump", "r") as f:
    file_bin = f.read()
    segments = json.loads(file_bin)

merged_segments = []

prev_base_address = 0
prev_data = b""
for segment in segments:
    base_address = int(segment["base_address"], 16)
    if prev_base_address + len(prev_data) == base_address:
        prev_data += base64.b64decode(segment["data"])
        merged_segments.pop()
    else:
        prev_base_address = base_address
        prev_data = base64.b64decode(segment["data"])
    merged_segments.append(
        {
            "base_address": prev_base_address,
            "length": len(prev_data),
            "data": prev_data,
        }
    )


def find_multiple(data, needle, align=1):
    index = 0
    out = []
    while True:
        index = data.find(needle, index)
        if index == -1:
            break
        out.append(index)
        index += align
    return out


def read_bytes(address, length=-1):
    for segment in merged_segments:
        base_address = segment["base_address"]
        if base_address <= address < base_address + segment["length"]:
            if length != -1:
                return segment["data"][
                    address - base_address : address - base_address + length
                ]
            else:  # read until \0
                return segment["data"][address - base_address : base_address].split(
                    b"\0", 1
                )[0]
    return b""


def search(needle, phase=0):
    for segment in merged_segments:
        base_address = segment["base_address"]
        if phase == 0 and needle in segment["data"]:
            locs = find_multiple(segment["data"], needle)
            for loc in locs:
                virtual_loc = base_address + loc
                search(struct.pack(f"<{pointer_size}", virtual_loc), 1)
        elif phase == 1 and needle in segment["data"]:
            locs = find_multiple(segment["data"], needle)
            for loc in locs:
                virtual_loc = base_address + loc
                unpack_sshenc(segment["data"][loc:], virtual_loc)


sshenc = {
    "32": {
        "name": (0, 4),  # char*
        "cipher": (4, 4),  # const struct sshcipher*
        "enabled": (8, 4),  # int
        "key_len": (12, 4),  # u_int
        "iv_len": (16, 4),  # u_int
        "block_size": (20, 4),  # u_int
        "key": (24, 4),  # u_char*
        "iv": (28, 4),  # u_char*
    },
    "64": {
        "name": (0, 8),  # char*
        "cipher": (8, 8),  # const struct sshcipher*
        "enabled": (16, 4),  # int
        "key_len": (20, 4),  # u_int
        "iv_len": (24, 4),  # u_int
        "block_size": (28, 4),  # u_int
        "key": (32, 8),  # u_char*
        "iv": (40, 8),  # u_char*
    },
}
sshenc = sshenc[arch]


def unpack_sshenc(data, sshenc_addr):
    name_addr = data[sshenc["name"][0] : sshenc["name"][0] + sshenc["name"][1]]
    cipher = data[sshenc["cipher"][0] : sshenc["cipher"][0] + sshenc["cipher"][1]]
    enable_bin = data[
        sshenc["enabled"][0] : sshenc["enabled"][0] + sshenc["enabled"][1]
    ]
    enabled = struct.unpack("<I", enable_bin)[0]
    key_len_bin = data[
        sshenc["key_len"][0] : sshenc["key_len"][0] + sshenc["key_len"][1]
    ]
    key_len = struct.unpack("<I", key_len_bin)[0]
    iv_len_bin = data[sshenc["iv_len"][0] : sshenc["iv_len"][0] + sshenc["iv_len"][1]]
    iv_len = struct.unpack("<I", iv_len_bin)[0]
    block_size_bin = data[
        sshenc["block_size"][0] : sshenc["block_size"][0] + sshenc["block_size"][1]
    ]
    block_size = struct.unpack("<I", block_size_bin)[0]
    key = data[sshenc["key"][0] : sshenc["key"][0] + sshenc["key"][1]]
    iv = data[sshenc["iv"][0] : sshenc["iv"][0] + sshenc["iv"][1]]
    name = read_bytes(struct.unpack(f"<{pointer_size}", name_addr)[0])

    if key_len > 255 or iv_len > 255 or block_size < 0 or block_size > 255:
        return
    if name is None or not all(c in string.printable.encode() for c in name):
        return
    if key_len == 0:
        return

    print("sshenc addrress", struct.pack(f">{pointer_size}", sshenc_addr).hex())
    print("name address", name_addr.hex())
    print("cipher address", cipher.hex())
    print(f"enabled {enabled} (0x{enable_bin.hex()})")
    print(f"key_len {key_len} (0x{key_len_bin.hex()})")
    print(f"iv_len {iv_len} (0x{iv_len_bin.hex()})")
    print(f"block_size {block_size} (0x{block_size_bin.hex()})")
    print("key address", key.hex())
    print("iv address", iv.hex())
    print("Name:", name)
    print("Key:", read_bytes(struct.unpack(f"<{pointer_size}", key)[0], key_len).hex())
    (
        print("IV:", read_bytes(struct.unpack(f"<{pointer_size}", iv)[0], iv_len).hex())
        if iv_len != 0
        else print("IV: None")
    )
    print("-------------------------------------")


search(b"aes128-ctr\0")

print("The last is generally the c_to_s while the first is the s_to_c.")

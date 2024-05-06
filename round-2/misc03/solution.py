import zlib

data = "aaaa1337beef0607326d6b7867355f0b411513aaaa1337beef02096e6130786f76723579c103aadcaaaa1337beef040731355f6e30375f8e94e162aaaa1337beef050a35305f683472645f3730891e91dfaaaa1337beef04073462776966777092d88aeaaaaa1337beef03043736697a69362837aaaa1337beef0a0433666633257f25a1aaaa1337beef0c05795f37305ff99d49abaaaa1337beef0d0a35683472335f35336372589a4240aaaa1337beef0b0863373176335f773495e8d7d6aaaa1337beef00076f70656e4543530449431eaaaa1337beef07066e645f31355facc9cf48aaaa1337beef06075f357030375f3461a371e2aaaa1337beef09045f346e5f31fe4211aaaa1337beef0804346c3530f06866e8aaaa1337beef090436616c6b0e2580b6aaaa1337beef0f05366537617dfb80a99aaaaa1337beef0e083337355f663537354f4a2ec2aaaa1337beef0104437b6635d91ae0e8aaaa1337beef02096b5f6d3064756c34374178e3bbaaaa1337beef030431306e5f4c95499b"

"""
packet structure
- 2 byte magic (0xAAAA)
- 2 byte src address
- 2 byte dest address
- 1 sequence number
- 1 byte length
- [lenght] bytes
- 4 byte crc32
"""

packets = []

c = 0
while c < len(data):
    magic = data[c : c + 4]
    if magic != "aaaa":
        c += 1
        continue

    src = data[c + 4 : c + 8]
    if src != "1337":
        c += 1
        continue

    dest = data[c + 8 : c + 12]
    seq = data[c + 12 : c + 14]
    length = data[c + 14 : c + 16]
    packet_data = data[c + 16 : c + 16 + int(length, 16) * 2]
    packet = data[c : c + 16 + int(length, 16) * 2]
    crc = data[c + 16 + int(length, 16) * 2 : c + 16 + int(length, 16) * 2 + 8]
    packet_for_crc = bytes.fromhex(src + dest + seq + length + packet_data)
    computed_crc = zlib.crc32(packet_for_crc).to_bytes(4, "big").hex()
    print()
    print(f"Magic: {magic}")
    print(f"Src: {src}")
    print(f"Dest: {dest}")
    print(f"Seq: {seq}")
    print(f"Length: {length}")
    print(f"Data: {packet_data}")
    print(f"Packet: {packet}")
    print(f"CRC: {crc} | COMPUTED: {computed_crc}")

    # validate CRC
    if crc != computed_crc:
        print("CRC Invalid")
        print()
        c += 1
        continue

    c += 16 + int(length, 16) * 2
    
    print()

    packets.append(
        {
            "magic": magic,
            "src": src,
            "dest": dest,
            "seq": seq,
            "length": length,
            "data": packet_data,
            "packet": packet,
            "crc": crc,
        }
    )

sorted_packets = sorted(packets, key=lambda x: x["seq"])
for p in sorted_packets:
    print(bytes.fromhex(p["data"]).decode("utf-8"), end="")
print()

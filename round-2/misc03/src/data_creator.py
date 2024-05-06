import socket
import random
import zlib
import binascii
import os, sys


def random_sting(length):
    return "".join(random.choices("abcdefghijklmnopqrstuvwxyz0123456789_", k=length))


"""
packet structure
- 2 byte magic (0xAAAA)
- 2 byte src address
- 2 byte dest address
- 1 sequence number
- 1 byte length
- lenght bytes
- 4 byte crc32
"""


def generate_packet(sequence_no, data, valid):
    packet = b"\x13\x37" + b"\xbe\xef"
    packet += sequence_no.to_bytes(1, "big")
    if valid:
        packet += len(data).to_bytes(1, "big") + data.encode()
        crc = zlib.crc32(packet).to_bytes(4, "big")
    else:
        packet += len(data).to_bytes(1, "big") + random_sting(len(data)).encode()
        crc = zlib.crc32(packet).to_bytes(4, "big")
        crc = crc[:-1] + bytes([crc[-1] ^ 0x42])
    return b"\xaa\xaa" + packet + crc


def to_bits(data):
    return "".join(format(byte, "08b") for byte in data)


def make_noise():
    return "".join(random.choices("01", k=random.randint(1, 100)))


def make_data(seed):
    random.seed(seed)

    FLAG = (
        "openECSC{f5k_m0dul4710n_15_n07_50_h4rd_70_5p07_4nd_15_4l50_4n_3ff3c71v3_w4y_70_5h4r3_53cr375_"
        + binascii.b2a_hex(random.randbytes(4)).decode()
        + "}"
    )
    print(f"Seed: {seed} | Flag: {FLAG}")
    print(f"===FLAG==={FLAG}===FLAG===")

    parts = []
    i = 0
    while i < len(FLAG):
        parts.append(FLAG[i : i + random.randint(4, 10)])
        i += len(parts[-1])
    assert FLAG == "".join(parts)

    packets = []
    for i, part in enumerate(parts):
        packets.append({"sequence": i, "data": part, "valid": True})
        if random.randint(1, 10) <= 3:
            packets.append({"sequence": i, "data": part, "valid": False})

    random.shuffle(packets)

    data = []
    for p in packets:
        # Encapsulate the message in a packet
        p = generate_packet(p["sequence"], p["data"], p["valid"])
        # Extact bits from the packet
        p = to_bits(p)

        # Add noise to the packet
        # p = p + make_noise()

        p = bytes([x - ord("0") for x in p.encode()])

        data.append(p)

    return data


def main():
    UDP_IP = "198.18.0.1"
    UDP_PORT = 1337

    client_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    data = make_data(sys.argv[1])
    for p in data:
        client_socket.sendto(p, (UDP_IP, UDP_PORT))


if __name__ == "__main__":
    main()

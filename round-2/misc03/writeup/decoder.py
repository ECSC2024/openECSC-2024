import sys
import zlib

"""
packet structure
- 2 byte magic (0xAAAA)
- 2 byte src address
- 2 byte dest address
- 1 byte length
- lenght bytes
- 2 byte crc16
"""

def pop_bytes(data, n):
    ret = data[:n*8]
    data = data[n*8:]
    return ret, data


def to_bytes(data):
    data = int(data, 2)
    return data.to_bytes((data.bit_length() + 7) // 8, 'big')


def check_crc(data, checksum):
    print(f'data: {data}')
    print(f'checksum: {checksum}')
    print(f'computed: {zlib.crc32(data)}')
    return zlib.crc32(data).to_bytes(4, 'big') == checksum


def main():
    with open(sys.argv[1], 'rb') as f:
        data = f.read()
    
    data = [x + ord('0') for x in data]
    data = bytes(data)
    data = data.decode()

    sync_word = '1010101010101010'

    # Find the sync word
    while len(data) > 0:
        if data[:len(sync_word)] != sync_word:
            data = data[1:]
            continue

        sync, data = pop_bytes(data, 2)
        src, data = pop_bytes(data, 2)
        dst, data = pop_bytes(data, 2)
        length, data = pop_bytes(data, 1)

        sync = to_bytes(sync)
        src = to_bytes(src)
        dst = to_bytes(dst)
        length = to_bytes(length)[0]
        print(f"src: {src}")
        print(f"dst: {dst}")
        print(f"length: {length}")

        payload, data = pop_bytes(data, length)
        crc, data = pop_bytes(data, 4)

        payload = to_bytes(payload)
        print(f"payload: {payload}")

        crc = to_bytes(crc)

        if check_crc((src + dst + bytes([length]) + payload), crc):
            print("CRC OK")
        else:
            print("CRC FAIL")
        

if __name__ == "__main__":
    main()
import binascii
from Crypto.Cipher import AES
from Crypto.Util import Counter

'''
tshark -r capture.pcapng -q -z follow,tcp,raw,0 > comm.txt

Get the keys with parse.py
'''

# Client to server
c_to_s_key = binascii.unhexlify("152c87eb67265def5d2aa66a7315848b")
c_to_s_iv = binascii.unhexlify("725f6e8a27ba25e7e30e318088c26963")

# Server to client
s_to_c_key = binascii.unhexlify("3e7c18148adab55b90cf07a7934f960f")
s_to_c_iv = binascii.unhexlify("57b9736f43a023d701316331f05e6c1e")


class Framer:
    def __init__(self, rows):
        self.rows = rows
        self.row_num = 2  # Skip banners
        self.row_offset = 0
        self.encrypted = {
            "S->C": False,
            "C->S": False,
        }

    def next_frame(self):
        if self.row_offset == len(self.rows[self.row_num]["data"]):
            self.row_num += 1
            self.row_offset = 0
            if self.row_num == len(self.rows):
                return None

        direction = self.rows[self.row_num]["direction"]
        row_og = self.rows[self.row_num]["data"]
        row = row_og[self.row_offset :]
        length = int.from_bytes(row[0:4], "big")

        frame = row[
            4
            + (0 if self.encrypted[direction] else 1) : length
            + 4
            + (0 if self.encrypted[direction] else 1)
        ]
        self.row_offset += 4 + length + (8 if self.encrypted[direction] else 0)

        if self.row_offset > len(row_og):
            print("ERROR", self.row_num, self.row_offset, len(row_og), length, row, row_og)
            return None

        return {
            "direction": direction,
            "data": frame,
        }


def hex_to_rows(hex_str):
    if hex_str[0] == "\t":
        direction = "S->C"
    else:
        direction = "C->S"
    return {"direction": direction, "data": binascii.unhexlify(hex_str.strip())}


framer = Framer(list(map(hex_to_rows, open("comm.txt").readlines())))

ciphers = {}
def decrypt_aes_ctr(direction, key, iv, data):
    global ciphers
    if direction not in ciphers:
        ciphers[direction] = AES.new(
            key,
            AES.MODE_CTR,
            counter=Counter.new(128, initial_value=int(binascii.hexlify(iv), 16)),
        )

    return ciphers[direction].decrypt(data)

encrypted = {"S->C": False, "C->S": False}
while True:
    frame = framer.next_frame()
    if frame is None:
        break
    direction = frame["direction"]
    data = frame["data"]
    
    if direction == "S->C":
        key = s_to_c_key
        iv = s_to_c_iv
    else:
        key = c_to_s_key
        iv = c_to_s_iv
        
    if not encrypted[direction]:
        print(direction, "PLN", data)

    if data[0:1] == b"\x15":
        encrypted[direction] = True
        framer.encrypted[direction] = True
        print(f'{direction} Encription starts now!')
        continue
        
    if encrypted[direction]:
        print(direction, "ENC", decrypt_aes_ctr(direction, key, iv, data))

import pyshark
from collections import defaultdict
from enum import Enum
from Crypto.Cipher import ChaCha20

KEYSET    = 0x74
NONCESET  = 0x11
STORE     = 0xC1
RESET     = 0xB8
ACK       = 0x14
ERROR     = 0xFF

streams = defaultdict(lambda: b"")
cap = pyshark.FileCapture("attachments/dump.pcapng")

for p in cap:
    try:
        i = int(p.tcp.stream)
        streams[i] += bytes.fromhex(p.data.data)
    except:
        pass
cap.close()

stream = streams[0]

kidxs = [i for i, x in enumerate(stream) if x == KEYSET]
nidxs = [i for i, x in enumerate(stream) if x == NONCESET]
print(f'{kidxs = }')
print(f'{nidxs = }')


def read():
    global stream
    s = stream[0]
    stream = stream[1:]
    return s

class Message():
    def __init__(self) -> None:
        self.code = None
        self.param = None
        self.len = None
        self.data = None
    
    def read(self):
        self.code = read()
        self.param = read()
        self.len = read()
        self.data = []
        for i in range(self.len):
            self.data.append(read())

    def handle(self):
        global KEY, IV, cipher, keyset, nonceset, cipherset
        match self.code:
            case 0x74:
                for i in range(32):
                    KEY[i] = self.data[i]
                keyset = True
                cipherset = False
            case 0x11:
                for i in range(8):
                    IV[i] = self.data[i]
                nonceset = True
                cipherset = False
            case 0xc1:
                if not keyset or not nonceset:
                    return
                if not cipherset:
                    cipherset = True
                    cipher = ChaCha20.new(key=bytes(KEY), nonce=bytes(IV))
                dec = cipher.decrypt(bytes(self.data))
                for i in range(self.len):
                    FLAG[10 * self.param + i] = dec[i]
                if -1 not in FLAG:
                    print(bytes(FLAG))
                    return True
            case 0xb8:
                KEY = [0] * 32
                IV = [0] * 8
                keyset = False
                nonceset = False
                cipherset = False

_stream = stream[:]
for ki in kidxs:
    for ni in nidxs:
        if ki > ni:
            continue

        print('key index:', ki, '\tnonce index:', ni)

        KEY = [-1] * 32
        IV = [-1] * 8
        FLAG = [-1] * 40
        keyset = False
        nonceset = False
        cipherset = False
        cipher = None

        try:
            stream = stream[ki:]
            m = Message()
            m.read()
            m.handle()

            stream = stream[ni-ki-35:]
            m = Message()
            m.read()
            m.handle()

            while len(stream)>0:
                ni = stream.index(NONCESET) if NONCESET in stream else 99999
                si = stream.index(STORE) if STORE in stream else 99999
                next_idx = min([ni, si])
                stream = stream[next_idx:]
                m = Message()
                m.read()
                if m.handle():
                    break
        except:
            print('Exception')
            pass
        stream = _stream[:]

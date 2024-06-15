# OliCyber.IT 2024 - National Final

## [misc] so far so good (15 solves)

I'm far from home and pushed a secret to my Arduino over the network... hope nobody finds out!

Author: Andrea Raineri <@Rising>

## Overview

The challenge consists of an Arduino sketch that reads a secret from the serial port and stores it in a global variable. The connection to the Arduino board is performed over the USB serial port, then exposed over the local IP network using the Linux `usbip` kernel module.

Two attachments are provided:
- Arduino sketch executed on the board
- network capture of the TCP/IP traffic between the client and the Arduino board

## Solution

Analyzing the Arduino sketch we can see that the secret is being transmitted encrypted with ChaCha20 after a key exchange. We can extract the key and nonce from the network capture and then decrypt the secret.

In order to extract the custom protocol messages received by the Arduino board, we need to:

1. Extract the USB BULK-IN/BULK-OUT packets from the TCP stream in the network capture
2. Extract the custom protocol messages from the USB packets

After extracting all the messages,

3. Extract the `key` from the message with opcode `0x74`
4. Extract the `nonce` from the message with opcode `0x11`
5. Recover `ciphertext` concatenating the content of all the messages with opcode `0xC1`
6. Decrypt the flag with `ChaCha20(key, nonce, ciphertext)`

### Alternative (proposed) solution
The proposed solution exploits the small size of the network traffic dump, which allows to try bruteforcing all positions of custom protocols opcodes without the need to parse and extract USB packets inside TCP segments. After looking for all potential KEYSET and NONCESET messages, all combinations are tested to initialize the cipher and search for STORE messages containing the encrypted flag.

## Exploit

```python
import pyshark
from collections import defaultdict
from Crypto.Cipher import ChaCha20
import sys

KEYSET    = 0x74
NONCESET  = 0x11
STORE     = 0xC1
RESET     = 0xB8
ACK       = 0x14
ERROR     = 0xFF

streams = defaultdict(lambda: b"")
cap = pyshark.FileCapture(f"dump.pcapng")

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
            case KEYSET:
                for i in range(32):
                    KEY[i] = self.data[i]
                keyset = True
                cipherset = False
            case NONCESET:
                for i in range(8):
                    IV[i] = self.data[i]
                nonceset = True
                cipherset = False
            case STORE:
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
            case RESET:
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
```
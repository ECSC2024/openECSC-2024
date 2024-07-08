# TeamItaly Preselection CTF 2024

## [misc] Flat-Sat (0 solves)

The software of our ground-station stopped working, however we still have the radio decoder which spits out the decoder bitstream.
The satellite we're trying to decode follows [this](https://public.ccsds.org/Pubs/131x0b5.pdf) specification

`nc flatsat.challs.external.open.ecsc2024.it 38316`

Author: Aleandro Prudenzano <@drw0if>

## Overview

The challenge gives us a netcat service which spits out single bits.
The idea is that the bitstream is the one produced by a radio demodulator, so we need to understand where the packets (actually frames) starts, understand the encoding scheme and decode them.

The attached standard specifies various different encoding scheme because the protocol has some parts which are managed (which means that are decided during the implementation and can't be read from the headers, for example) however, some of those can be recovered through some observations.

## Solution

### Frame boundaries

First thing first we need to understand where in the bitstream the frames are located.
Based on the coding system we can have:

- an Attached Sync Marker (ASM) preceding the actual frame: for Reed-Solomon, Turbo and LDPC coding
- an ASM in the domain of bits decoded by the relative decoder: for the convolutional codes and some of the other encoding schemes.

Since we have no specific information about the encoding scheme we can try the various ASM bit patterns, in particular the one that is found realiably inside the bitstream is the one in the figure `9-1`:

```python
ASM = [0, 0, 0, 1, 1, 0, 1, 0, 1, 1, 0, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 1, 1, 1, 0, 1]
```

which is for `ASM Bit Pattern for Uncoded, Convolutional, Reed-Solomon, Concatenated, Rate 7/8 LDPC (Applied to a Transfer Frame), and all LDPC (Applied to a Stream of SMTFs) Coded Data`

Looking at the appearance of this sequence we can notice that it is reliably found with 4112 bits of displacement from one to another (and sometimes with some more displacement), from this we can educately guess that the frame size, before the decoding, is `510 bytes` in size (remove the 4 bytes of ASM).

### Coding scheme

Since we've found the ASM we are restricted to some encoding, moreover we have the size so we can try to understand which coding scheme is used:

- uncoded: the data are not encoded and the size can be a generic number of bytes up to 2048 (section 11.3)
- convolutional: data are encoded with convolutional coding and the size can be any bytes up to 2048 (section 11.4)
- reed-solomon: data are encoded with reed-solomon and the size is an integer multiple of `255` (section 4.3.6), it could be our case because with 2 as interleaving we have `2*255 = 510`
- rate 7/8 LDPC: the transfer frame length is 892 bytes (section 11.8.2), so definitely not our case
- all LDPC applied to a stream of SMTFs: the transfer frame length is 2048 bytes at least (for TM), so definitely not our case

We are restricted to uncoded, convolutional and reed-solomon, however the size of the reed-solomon is particularly shady.

### Data de-randomization

Both convolutional and reed-solomon coding specify data randomization (sections 3.2.2 and 4.2.1) in order to improve the bit transitions number.
The randomization is specified in section 10: it specifies two LFSRs that produce pseudo-random sequences.
We can pre-generate both sequeces and test both of them.

After testing with both sequences we can notice that with the second one we have some readable data, but sometimes it is corrupted.

(it seems that at this point the challenge is already solved because re-running the decoding more times we can take the correct flag for sure in 2-3 runs, I did not notice it during the development, but still, thanks to @dp_1 !!)

### Data decoding

The easier of the two to test for is reed-solomon, this is because reed-solomon decoding does not work if the data you give it is wrong, so we have a direct feedback.

We can use [this](https://pypi.org/project/reed-solomon-ccsds/) implementation, the interleaving is 2 as we found out before and we can test with both `dual_basis=True` and `dual_basis=False`.

The reed-solomon decoding works and so we get the corrected flag.

## Exploit

```py
#!/usr/bin/env python3

import logging
import os
from pwn import remote
import reed_solomon as rs

logging.disable()

HOST = os.environ.get("HOST", "flatsat.challs.external.open.ecsc2024.it")
PORT = int(os.environ.get("PORT", 38316))

ASM = [0, 0, 0, 1, 1, 0, 1, 0, 1, 1, 0, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 1, 1, 1, 0, 1]
ASM = ''.join([str(x) for x in ASM])


def CRC(data, crc=0xffff):
    for d in data:
        crc = (crc >> 8) | (crc << 8)
        crc ^= d
        crc ^= (crc & 0xff) >> 4
        crc ^= (crc << 8) << 4
        crc ^= ((crc & 0xff) << 4) << 1
        crc &= 0xffff

    return crc


randomizer_CCSDS = [0xFF, 0x48, 0x0E, 0xC0, 0x9A, 0x0D, 0x70, 0xBC,
                    0x8E, 0x2C, 0x93, 0xAD, 0xA7, 0xB7, 0x46, 0xCE,
                    0x5A, 0x97, 0x7D, 0xCC, 0x32, 0xA2, 0xBF, 0x3E,
                    0x0A, 0x10, 0xF1, 0x88, 0x94, 0xCD, 0xEA, 0xB1,
                    0xFE, 0x90, 0x1D, 0x81, 0x34, 0x1A, 0xE1, 0x79,
                    0x1C, 0x59, 0x27, 0x5B, 0x4F, 0x6E, 0x8D, 0x9C,
                    0xB5, 0x2E, 0xFB, 0x98, 0x65, 0x45, 0x7E, 0x7C,
                    0x14, 0x21, 0xE3, 0x11, 0x29, 0x9B, 0xD5, 0x63,
                    0xFD, 0x20, 0x3B, 0x02, 0x68, 0x35, 0xC2, 0xF2,
                    0x38, 0xB2, 0x4E, 0xB6, 0x9E, 0xDD, 0x1B, 0x39,
                    0x6A, 0x5D, 0xF7, 0x30, 0xCA, 0x8A, 0xFC, 0xF8,
                    0x28, 0x43, 0xC6, 0x22, 0x53, 0x37, 0xAA, 0xC7,
                    0xFA, 0x40, 0x76, 0x04, 0xD0, 0x6B, 0x85, 0xE4,
                    0x71, 0x64, 0x9D, 0x6D, 0x3D, 0xBA, 0x36, 0x72,
                    0xD4, 0xBB, 0xEE, 0x61, 0x95, 0x15, 0xF9, 0xF0,
                    0x50, 0x87, 0x8C, 0x44, 0xA6, 0x6F, 0x55, 0x8F,
                    0xF4, 0x80, 0xEC, 0x09, 0xA0, 0xD7, 0x0B, 0xC8,
                    0xE2, 0xC9, 0x3A, 0xDA, 0x7B, 0x74, 0x6C, 0xE5,
                    0xA9, 0x77, 0xDC, 0xC3, 0x2A, 0x2B, 0xF3, 0xE0,
                    0xA1, 0x0F, 0x18, 0x89, 0x4C, 0xDE, 0xAB, 0x1F,
                    0xE9, 0x01, 0xD8, 0x13, 0x41, 0xAE, 0x17, 0x91,
                    0xC5, 0x92, 0x75, 0xB4, 0xF6, 0xE8, 0xD9, 0xCB,
                    0x52, 0xEF, 0xB9, 0x86, 0x54, 0x57, 0xE7, 0xC1,
                    0x42, 0x1E, 0x31, 0x12, 0x99, 0xBD, 0x56, 0x3F,
                    0xD2, 0x03, 0xB0, 0x26, 0x83, 0x5C, 0x2F, 0x23,
                    0x8B, 0x24, 0xEB, 0x69, 0xED, 0xD1, 0xB3, 0x96,
                    0xA5, 0xDF, 0x73, 0x0C, 0xA8, 0xAF, 0xCF, 0x82,
                    0x84, 0x3C, 0x62, 0x25, 0x33, 0x7A, 0xAC, 0x7F,
                    0xA4, 0x07, 0x60, 0x4D, 0x06, 0xB8, 0x5E, 0x47,
                    0x16, 0x49, 0xD6, 0xD3, 0xDB, 0xA3, 0x67, 0x2D,
                    0x4B, 0xBE, 0xE6, 0x19, 0x51, 0x5F, 0x9F, 0x05,
                    0x08, 0x78, 0xC4, 0x4A, 0x66, 0xF5, 0x58]


def derandomize(data):
    return bytes(d ^ randomizer_CCSDS[i % len(randomizer_CCSDS)] for i, d in enumerate(data))


def bits2bytes(data):
    bits = "".join(map(str, data))
    return bytes(int(bits[i:i + 8], 2) for i in range(0, len(bits), 8))


class bitsreader:
    def __init__(self, data, size):
        self.data = data
        # conver the data to bits
        if type(data) == bytes:
            self.data = ''.join(format(byte, '08b') for byte in data).rjust(size, '0')
        if type(data) == int:
            self.data = bin(data)[2:].rjust(size, '0')
        self.pos = 0

    def read(self, size):
        value = int(self.data[self.pos:self.pos + size], 2)
        self.pos += size
        return value


class FrameHeaderTM:
    def dissect(self, data) -> bytes:
        ccsds_header = bitsreader(data[:6], 6 * 8)

        # 2 bits for tf version number
        self.tf_version_number = ccsds_header.read(2)
        # 10 bits for spacecraft ID 
        self.spacecraft_id = ccsds_header.read(10)
        # 3 bits for virtual channel ID
        self.virtual_channel_id = ccsds_header.read(3)
        # 1 bit for ocf
        self.ocf = ccsds_header.read(1)
        # 8 bits master channel frame count
        self.mcfc = ccsds_header.read(8)
        # 8 bits for virtual channel frame count
        self.vcfc = ccsds_header.read(8)
        # 16 bits for transfer frame data field status

        # 1 bit for transfer frame secondary header flag
        self.tfsh_flag = ccsds_header.read(1)
        # 1 bit for synchronization flag
        self.sf = ccsds_header.read(1)
        # 1 bit for packet order flag
        self.pof = ccsds_header.read(1)
        # 2 bits for segment length identifier
        self.sli = ccsds_header.read(2)
        # 11 bits for first header pointer
        self.fhp = ccsds_header.read(11)
        return data[6:]


class FrameSecondaryHeaderTM:
    def dissect(self, data) -> bytes:
        ccsds_secondary_header = bitsreader(data[:2], 2 * 8)
        # 2 bits for tf version number
        self.tf_version_number = ccsds_secondary_header.read(2)
        # 6 bits for transfer frame secondary header length
        self.tfsh_length = ccsds_secondary_header.read(6)
        # data header
        self.data_header = data[2:2 + self.tfsh_length]
        return data[2 + self.tfsh_length:]


class FrameTM:
    def __init__(self, crc=True):
        self.crc_flag = crc

        self.header = FrameHeaderTM()
        self.secondary_header = None
        self.ocf = None
        self.crc = None

    def dissect(self, frame_data, security_header_length=0):
        self.frame_data = frame_data
        self.l = len(frame_data)
        data = self.header.dissect(frame_data)
        if self.header.tfsh_flag:
            self.secondary_header = FrameSecondaryHeaderTM()
            data = self.secondary_header.dissect(data)

        if self.crc_flag:
            self.crc = int.from_bytes(data[-2:], 'big')
            data = data[:-2]
            if CRC(frame_data[:-2]) != self.crc:
                print(f"CRC: {CRC(frame_data[:-2])}")
                print(f"CRC with all: {CRC(frame_data)}")
                print(f"CRC computed: {self.crc}")
                raise ValueError("Checksum Invalid")

        if self.header.ocf:
            self.ocf = int.from_bytes(data[-4:], 'big')
            data = data[:-4]

        self.data = data

    def is_valid(self):
        return CRC(self.frame_data[:-2]) == self.crc


def decode_frame(data, interleaving=2):
    assert data[:len(ASM)] == ASM
    data = data[len(ASM):]

    # descramble
    data = bits2bytes(data)
    data = derandomize(data)

    # reed solomon
    data = rs.decode(data, dual_basis=True, interleaving=interleaving)

    return data


def main():
    r = remote(HOST, PORT)

    guessed_interleaving = 2
    TM_packet_size = 223
    # frame size = TM_packet_size * interleaving + size(R-S check symbols)
    frame_length = TM_packet_size * guessed_interleaving + 64

    data = ''

    try:
        while (tmp := r.recv(1024)) is not None:
            tmp = tmp.decode('ascii')
            data += ''.join([str(x) for x in tmp])

            if (pos := data.find(ASM)) != -1:
                # Remove gibberish from starting of the data
                data = data[pos:]

                # Extract maybe frame with ASM
                maybe_packet = data[:len(ASM) + frame_length * 8]

                # Check size
                if len(maybe_packet) < len(ASM) + frame_length * 8:
                    continue

                data = data[len(ASM) + frame_length * 8:]

                try:
                    _, maybe_packet = decode_frame(maybe_packet, guessed_interleaving)
                except ValueError:
                    print("ERROR")
                    continue

                frame = FrameTM()
                frame.dissect(maybe_packet)

                if frame.is_valid():
                    print(frame.data.rstrip(b"\x00").decode('ascii'))
                else:
                    print("Invalid frame")

    except EOFError:
        print("Done")


main()
```

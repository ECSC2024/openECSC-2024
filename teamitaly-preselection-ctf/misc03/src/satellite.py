import reed_solomon_ccsds as rs
import random
import os

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


class bitswriter:
    def __init__(self, size):
        self.data = ''
        self.size = size

    def write(self, value, size):
        v = bin(value)[2:].rjust(size, '0')
        if len(v) != size:
            raise ValueError("Value too large")
        self.data += v

    def get(self):
        return int(self.data, 2).to_bytes(self.size//8, 'big')


class FrameHeaderTM:
    def __init__(self):
        self.tf_version_number = 0
        self.spacecraft_id = 0
        self.virtual_channel_id = 0
        self.ocf = 0
        self.mcfc = 0
        self.vcfc = 0
        self.tfdf = 0
        self.tfsh_flag = 0
        self.sf = 0
        self.pof = 0
        self.sli = 0
        self.fhp = 0

    def set(self, virtual_channel_id, mcfc, vcfc, tf_version_number=0, spacecraft_id=0x3ff, ocf=0, tfsh_flag=0, sf=0, pof=0, sli=3, fhp=0):
        self.tf_version_number = tf_version_number
        self.spacecraft_id = spacecraft_id
        self.virtual_channel_id = virtual_channel_id
        self.ocf = ocf
        self.mcfc = mcfc
        self.vcfc = vcfc
        self.tfsh_flag = tfsh_flag
        self.sf = sf
        self.pof = pof
        self.sli = sli
        self.fhp = fhp
        

    def build(self) -> bytes:
        writer = bitswriter(6*8)
        writer.write(self.tf_version_number, 2)
        writer.write(self.spacecraft_id, 10)
        writer.write(self.virtual_channel_id, 3)
        writer.write(self.ocf, 1)
        writer.write(self.mcfc, 8)
        writer.write(self.vcfc, 8)
        writer.write(self.tfsh_flag, 1)
        writer.write(self.sf, 1)
        writer.write(self.pof, 1)
        writer.write(self.sli, 2)
        writer.write(self.fhp, 11)
        return writer.get()


class FrameSecondaryHeaderTM:
    def __init__(self):
        self.tf_version_number = 0
        self.tfsh_length = 0
        self.data_header = b""

    def set(self, tf_version_number, tfsh_length, data_header):
        self.tf_version_number = tf_version_number
        self.tfsh_length = tfsh_length
        self.data_header = data_header

    def build(self) -> bytes:
        writer = bitswriter(2*8)
        writer.write(self.tf_version_number, 2)
        writer.write(self.tfsh_length, 6)
        return writer.get() + self.data_header


class FrameTM:
    def __init__(self, crc=True):
        self.crc_flag = crc

        self.header = FrameHeaderTM()
        self.secondary_header = None
        self.ocf = None
        self.crc = None
        self.security_header = b""


    def set(self, header: FrameHeaderTM, data: bytes, l=1115, secondary_header: FrameSecondaryHeaderTM|None = None, ocf: int|None = None, security_header=b"") -> bytes:
        self.header = header
        self.data = data
        self.secondary_header = secondary_header
        self.ocf = ocf
        self.l = l
        self.security_header = security_header


    def build(self) -> bytes:
        self.frame_data = self.header.build()
        if self.secondary_header is not None:
            self.frame_data += self.secondary_header.build()
        self.frame_data += self.security_header
        self.frame_data += self.data
        trailer = 0 + 4 if self.ocf is not None else 0 + 2 if self.crc_flag else 0
        self.frame_data = self.frame_data.ljust(self.l - trailer, b"\x00")
        if self.ocf is not None:
            self.frame_data += int.to_bytes(self.ocf, 4, 'big')
        if self.crc_flag:
            self.crc = CRC(self.frame_data)
            self.frame_data += int.to_bytes(self.crc, 2, 'big')
        return self.frame_data


# unpack bytes into bits
def bytes2bits(data):
    return [int(b) for byte in data for b in format(byte, '08b')]


def derandomize(data):
    return bytes(d ^ randomizer_CCSDS[i % len(randomizer_CCSDS)] for i, d in enumerate(data))


def encode_frame(frame: bytes, interleaving=5, ASM=[0, 0, 0, 1, 1, 0, 1, 0, 1, 1, 0, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 1, 1, 1, 0, 1]):
    if len(frame) > interleaving*223:
        raise ValueError("Frame too long")
    # encode the frame with reed solomon code
    msg = frame.ljust(interleaving*223, b"\x00")
    msg = rs.encode(msg, dual_basis=True, interleaving=interleaving)
    
    # scramble the data with CCSDS randomizer
    msg = derandomize(msg)
    
    # add ASM
    msg = ASM + bytes2bits(msg)
    
    # to list of int
    msg = list(msg)
    return msg


def send_random_noise():
    for _ in range(random.randint(0, 200)):
        print(random.randint(0, 1), end='')

def build_telemetry():
    telemetry = b""
    telemetry += f"LAT: {random.uniform(-90, 90):.6f} - ".encode()
    telemetry += f"LON: {random.uniform(-180, 180):.6f} - ".encode()
    telemetry += f"ALT: 10000 - ".encode()
    telemetry += f"TILT: {random.uniform(0, 180):.6f}".encode()
    return telemetry


def main():
    FLAG = os.environ.get('FLAG', 'flag').encode()

    frame_count = 0

    for _ in range(10):
        send_random_noise()

        messages = [
            build_telemetry() for x in range(5)
        ]
        messages += [FLAG]
        messages += [
            build_telemetry() for x in range(10)
        ]


        for m in messages:
            # Build the frame header
            frame_header = FrameHeaderTM()
            frame_header.set(
                virtual_channel_id = 2,
                mcfc = frame_count,
                vcfc = frame_count
            )

            frame_count += 1

            # Build the frame
            frame = FrameTM()
            frame.set(
                header=frame_header,
                data=m,
                l=446,
                secondary_header=None
            )

            packet = frame.build()
            packet = encode_frame(packet, interleaving=2)

            if random.randint(0, 1) == 0:
                start_burst = random.randint(32, len(packet)-1)
                end_burst = start_burst + random.randint(0, 100)
                burst_type = random.randint(0, 2)

                burst = []

                if burst_type == 0:
                    burst = [0] * (end_burst - start_burst)
                elif burst_type == 1:
                    burst = [1] * (end_burst - start_burst)
                else:
                    burst = [random.randint(0, 1) for _ in range((end_burst - start_burst))]

                packet[start_burst:end_burst] = burst

            for x in packet:
                print(x, end='')

        send_random_noise()


if __name__ == '__main__':
    main()

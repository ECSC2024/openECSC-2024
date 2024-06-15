import os
import serial
from time import sleep
from Crypto.Cipher import ChaCha20

# Open the serial port
ser = serial.Serial('/dev/ttyACM0', 9600, timeout=1)
sleep(5)

message_codes = {
    'KEYSET': 0x74,
    'NONCESET': 0x11,
    'STORE': 0xC1,
    'RESET': 0xB8,
    'ACK': 0x14,
    'ERROR': 0xFF
}

def send_message(code: str, param: int, data: bytes):
    o = bytes([message_codes[code], param, len(data)]) + data
    print(f"Sending: {o}")
    ser.write(o)

def receive_message():
    message = {
        'code': ser.read(1)[0],
        'param': ser.read(1)[0],
        'length': ser.read(1)[0]
    }
    message['data'] = ser.read(message['length'])
    return message

key = os.urandom(32)
nonce = os.urandom(8)
cipher = ChaCha20.new(key=key, nonce=nonce)

FLAG = b'flag{0h_usb_0v3r_1p_i5_s0_c00l_24c6783a}'

send_message('RESET', 0, b'')
response = receive_message()
print(response)
if response['code'] != message_codes['ACK']:
    print('Error resetting device')
    exit(1)

send_message('KEYSET', 1, key)
response = receive_message()
print(response)
if response['code'] != message_codes['ACK']:
    print('Error setting key')
    exit(1)

send_message('NONCESET', 0, nonce)
response = receive_message()
print(response)
if response['code'] != message_codes['ACK']:
    print('Error setting nonce')
    exit(1)

for x in range(4):
    send_message('STORE', x, cipher.encrypt(FLAG[x*10:x*10+10]))
    response = receive_message()
    print(response)
    if response['code'] != message_codes['ACK']:
        print(f'Error storing data \'{FLAG[x*10:x*10+10]}\'')
        exit(1)

send_message('RESET', 0, b'')
response = receive_message()
print(response)
if response['code'] != message_codes['ACK']:
    print('Error resetting device')
    exit(1)

ser.close()

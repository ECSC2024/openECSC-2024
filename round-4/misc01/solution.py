from Crypto.Cipher import AES
from Crypto.Util import Counter
import sys
import subprocess
from PIL import Image
from pyzbar import pyzbar

if len(sys.argv) != 2:
    print(f"Usage: {sys.argv[0]} <pcap>")
    sys.exit(1)

capture = sys.argv[1]
out = subprocess.check_output(f"tshark -r {capture} -Y websocket -T fields -e tcp.stream -e text", shell=True).decode().strip().split('\n')

SIZE = 200
canvas = Image.new('RGB', (SIZE, SIZE), 'white')
pixels = canvas.load()
clients = {}

for l in out:
    l = l.split()
    stream = int(l[0])
    data = l[1]
    if data == "Timestamps" or "TOGGLE" in data:
        continue
    if "KEY" in l[1]:
        key = bytes.fromhex(data[15:])
        client = AES.new(key, AES.MODE_CTR, counter=Counter.new(128, initial_value=1337))
        clients[stream] = client
    else:
        data = clients[stream].decrypt(bytes.fromhex(data[11:])).decode()
        x, y, status = map(int, data.split(','))
        pixels[x,y] = (0,0,0) if status == 1 else (255,255,255)

# canvas.show()

decoded = pyzbar.decode(canvas)
print(decoded[0].data.decode())
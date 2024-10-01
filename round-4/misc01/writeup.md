# openECSC 2024 - Final Round

## [misc] Check da box (30 solves)

We made this awesome canvas to let you paint but someone is ruining our fun >:(

Author: Aleandro Prudenzano <@drw0if>, Lorenzo Catoni <@lorenzcat>

## Overview

The challenge gives a pcap capture file, containing mostly websocket traffic. Some of the packets contain HTTP requests to a web page, looking at the HTML of the page we can see that there's a 200x200 grid of checkboxes and some javascript that sends a websocket message to the server whenever a checkbox is checked or unchecked.  As the description suggests, the grid of checkboxes is like a canvas and the goal is to reconstruct the image that was drawn on it.

## Solution

The javascript inside the page looks like this:

```js
const TOGGLE_REGEX = /\d{1,3},\d{1,3},[01]/;
const KEY_REGEX = /KEY=([0-9a-fA-F]{32})/;
const TOGGLE_ENC_REGEX = /TOGGLE=([0-9a-fA-F]+)/;
const ws = new WebSocket(`ws://${location.host}/toggle`);
let encryptor = null;
let decryptor = null;
ws.onmessage = (event) => {
	const payload = event.data.toString();
	let match;
	if (match = payload.match(KEY_REGEX)) {
		const key = aesjs.utils.hex.toBytes(match[1]);
		console.log(key);
		encryptor = new aesjs.ModeOfOperation.ctr(key, new aesjs.Counter(1337));
		decryptor = new aesjs.ModeOfOperation.ctr(key, new aesjs.Counter(1337));
	}
	else if (match = payload.match(TOGGLE_ENC_REGEX)) {
		let plaintext = decryptor.decrypt(aesjs.utils.hex.toBytes(match[1]));
		plaintext = aesjs.utils.utf8.fromBytes(plaintext);
		if (!plaintext.match(TOGGLE_REGEX)) {
			console.log("Invalid decryption");
			return;
		}
		const [i, j, checked] = plaintext.split(",").map(Number);
		const checkbox = document.getElementById(`checkbox-${i}-${j}`);
		checkbox.checked = checked;
	}
	else {
		console.log(`invalid message: ${payload}`);
	}
}

ws.onopen = () => {
	console.log("Connected to server");
}

const check = async (i, j) => {
	const checkbox = document.getElementById(`checkbox-${i}-${j}`);
	const payload = encryptor.encrypt(aesjs.utils.utf8.toBytes(`${i},${j},${Number(checkbox.checked)}`));
	console.log(aesjs.utils.hex.fromBytes(payload));
	ws.send(aesjs.utils.hex.fromBytes(payload));
}
```

So the websocket messages are encrypted, but the key is sent in the clear in the first message, so the messages can be easily decrypted.
It's possible to extract all the websocket messages with the following tshark command (printing also the tcp stream since the aes key changes on each new connection):

```sh
tshark -r checkdabox.pcap -Y websocket -T fields -e tcp.stream -e text
```

From here we just need to parse the messages, knowing that the first message contains the key and the following messages contain the encrypted coordinates of the checkboxes that were toggled, like so:

```py
out = ... # output of tshark
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
```

The resulting image is a QR code that contains the flag.

## Exploit

```py
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
```
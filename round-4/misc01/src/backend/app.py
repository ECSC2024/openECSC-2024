import os
from flask import Flask, render_template
from flask_sock import Sock
from BitVector import BitVector
from threading import Lock
from Crypto.Cipher import AES
from Crypto.Util import Counter

SIZE = 200
canvas = BitVector(size = SIZE*SIZE)
clients = []
mut = Lock()

app = Flask(__name__)
sock = Sock(app)


@app.route('/', methods=['GET'])
def index():
    return render_template('index.html', SIZE=SIZE, canvas=canvas)

class EncryptedClient:
    def __init__(self, ws):
        self.ws = ws
        key = os.urandom(16)
        ws.send(f"KEY={key.hex()}")
        self.encryptor = AES.new(key, AES.MODE_CTR, counter=Counter.new(128, initial_value=1337))
        self.decryptor = AES.new(key, AES.MODE_CTR, counter=Counter.new(128, initial_value=1337))
    
    def send(self, data: str):
        self.ws.send(f"TOGGLE={self.encryptor.encrypt(data.encode()).hex()}")
    
    def receive(self) -> str:
        # raises an exception if the client disconnects (or if ws.receive() returns None either way we want to stop)
        return self.decryptor.decrypt(bytes.fromhex(self.ws.receive())).decode()
    
    def __eq__(self, other):
        return self.ws == other.ws

@sock.route('/toggle')
def toggle(ws):

    client = EncryptedClient(ws)
    clients.append(client)

    try:
        while True:
            data = client.receive()
            if data is None:
                break

            try:
                x, y, status = map(int, data.split(','))
                index = x + y * SIZE
            except ValueError:
                continue

            with mut:
                canvas[index] = status

                for c in clients:
                    if c == client:
                        continue
                    try:
                        c.send(f'{x},{y},{canvas[index]}')
                    except Exception as e:
                        print(f"Can't talk to client {client}: {e}")

                # client.send("Done")
    except Exception as e:
        print(f"Client disconnected")
        print(e)
    finally:
        clients.remove(client)
        print(f"Removing client from list")


if __name__ == '__main__':
    app.run(debug=True, host="0.0.0.0", port=5000)
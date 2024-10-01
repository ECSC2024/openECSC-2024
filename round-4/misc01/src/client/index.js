const qrcode = require("qrcode");
var pixels = require("image-pixels");
const { assert } = require("console");
const ws = require("ws");
const shuffle = require("shuffle-array");
const aesjs = require("aes-js");

const HOST = process.env.HOST || "localhost:5000";
const HTTP_URL = `http://${HOST}/`;
const WS_URL = `ws://${HOST}/toggle`;
const SIZE = 200;
const FLAG = process.env.FLAG || "openECSC{h3ll0_my_f3ll0w_7w1773r_3nj0y3r_XXXXXXXX}";

const coords2idx = (x, y, width) => (y * width + x) * 4;

function splitMessages(messages, nWorkers) {
  let j = 0;
  const result = Array(nWorkers).fill(0).map(() => []);
  while (true) {
    for (let r in result) {
      if (j >= messages.length)
        return result;

      if (Math.random() < 0.5)
        result[r].push(messages[j++]);
    }
  }
}

const TOGGLE_REGEX = /\d{1,3},\d{1,3},[01]/;
const KEY_REGEX = /KEY=([0-9a-fA-F]{32})/;
const TOGGLE_ENC_REGEX = /TOGGLE=([0-9a-fA-F]+)/;
class EncryptedWs extends ws.WebSocket {
  constructor(url, onmsg) {
    super(url);
    this.encryptor = null;
    this.decryptor = null;
    let self = this;

    this.onmessage = (event) => {
      const payload = event.data.toString();
      let match;
      if ((match = payload.match(KEY_REGEX))) {
        const key = aesjs.utils.hex.toBytes(match[1]);
        console.debug(`key= ${key}`);
        self.encryptor = new aesjs.ModeOfOperation.ctr(key, new aesjs.Counter(1337));
        self.decryptor = new aesjs.ModeOfOperation.ctr(key, new aesjs.Counter(1337));
      } else if ((match = payload.match(TOGGLE_ENC_REGEX))) {
        let plaintext = self.decryptor.decrypt(aesjs.utils.hex.toBytes(match[1]));
        plaintext = aesjs.utils.utf8.fromBytes(plaintext);
        if (!plaintext.match(TOGGLE_REGEX)) {
          console.error("Invalid decryption");
          return;
        }
        const [i, j, checked] = plaintext.split(",").map(Number);
        onmsg && onmsg({ i, j, checked });
      } else {
        console.error(`invalid message: ${payload}`);
      }
    };
  }

  send(str) {
    const textBytes = aesjs.utils.utf8.toBytes(str);
    const encryptedBytes = this.encryptor.encrypt(textBytes);
    const encryptedHex = aesjs.utils.hex.fromBytes(encryptedBytes);
    super.send(encryptedHex);
  }
}

(async () => {
  const img = await qrcode.toDataURL(FLAG);

  const { data, width, height } = await pixels(img);
  console.log(`Image size: ${width}x${height}`);

  assert(
    (width * height) / 4 <= SIZE * SIZE,
    "Flag too long to fit in the grid"
  );

  // Correct if another agent toggles the pixels of the QR code
  const watcher = new EncryptedWs(WS_URL, ({i, j, checked}) => {
    const idx = coords2idx(i, j, width);
    if (idx > data.length) {
      return;
    }
    const color = data[idx];
    const corret_checked = color === 255 ? 0 : 1;

    if (checked !== corret_checked) {
      // console.log("Mismatch");
      watcher.send(`${i},${j},${corret_checked}`);
    }
  }); // /watcher

  let messages = [];
  for (let i = 0; i < width; i++) {
    for (let j = 0; j < height; j++) {
      const color = data[coords2idx(i, j, width)];
      const checked = color === 255 ? 0 : 1;
      messages.push([i,j,checked]);
    }
  }
  shuffle(messages);

  console.log(`Total messages: ${messages.length}`);

  // let nworkers = Math.random() * 10 + 1;
  let nworkers = 9;
  let splittedMessages = splitMessages(messages, nworkers);

  // select some messages at random and flip the bit
  let flippedMessages = Array(splittedMessages[0].length)
    .fill(0)
    .map(() => {
      let [i,j,checked] = messages[Math.floor(Math.random() * messages.length)];
      return [i,j,checked ^ 1];
    });

  nworkers += 1;
  splittedMessages.push(flippedMessages);

  let jobs = [];
  for (let worker_idx = 0; worker_idx < nworkers; worker_idx++) {
    await new Promise((r) => setTimeout(r, 1000)); // so they don't send all at the same time
    jobs.push(new Promise(async (resolve) => {
  	  let res = await fetch(HTTP_URL)
	  await res.text() // fetch page so html is in the capture

      const socket = new EncryptedWs(WS_URL);
      const messageSet = splittedMessages[worker_idx];

      socket.onopen = async () => {
        console.log(`Worker ${worker_idx} connected`);
        console.log(`Worker ${worker_idx} will send ${messageSet.length} messages`);

        for (let [i,j,checked] of messageSet) {
          await new Promise((r) => setTimeout(r, 33));
          socket.send(`${i},${j},${checked}`);
        }

        console.log(`Worker ${worker_idx} done`);
        socket.close();
        resolve();
      };

      socket.onerror = (error) => {
        console.log(`Error: ${error.message}`);
      };
    }));
  }

  await Promise.all(jobs);
  watcher.close();
})();

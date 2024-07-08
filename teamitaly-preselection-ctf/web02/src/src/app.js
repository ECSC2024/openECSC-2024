const express = require('express');
const session = require('express-session');
const {spawn} = require('child_process');
const multer = require('multer');
const fs = require('fs');
const crypto = require('crypto');
const puppeteer = require('puppeteer');
const {v4: uuidv4} = require('uuid');
const path = require('path');

// import hashcash.js
const verify_pow = require('./hashcash.js');
const BITS = 28;
const FLAG = 'TeamItaly{chrome://restart_1s_l0v3}'; // We don't use this


const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, __dirname + '/sandbox/' + req.session.sanbox_id + '/uploads/');
  },
  filename: (req, file, cb) => {

    let filename = decodeURIComponent(file.originalname);
    let upload_folder = path.join(__dirname, 'sandbox', req.session.sanbox_id);


    let file_path = path.normalize(path.join(upload_folder, 'uploads', filename));
    if (!file_path.startsWith(upload_folder)) {
      cb(new Error("Invalid path"));
    }

    if (fs.existsSync(file_path)) {
      cb(new Error('File already exists'));
    } else {
      cb(null, filename);
    }
  }
});

const upload = multer({storage});
const app = express();
app.use(session({
  secret: crypto.getRandomValues(new Uint32Array(1))[0].toString(),
  resave: false,
  saveUninitialized: false,
}));

app.use((req, res, next) => {
  console.log("Request from", req.ip, "to", req.path, req.session.sanbox_id)
  if (!req.session.sanbox_id) {
    req.session.sanbox_id = uuidv4();
    fs.mkdirSync(`/home/app/sandbox/${req.session.sanbox_id}/chromium`, {recursive: true});
    fs.mkdirSync(`/home/app/sandbox/${req.session.sanbox_id}/uploads`, {recursive: true});

  }
  if (!req.session.pow) {
    // generate 6 random bytes
    req.session.pow = crypto.randomBytes(6).toString('hex');
  }
  next();
})


app.get('/', (req, res) => {
  res.send(`Hello World! Sandbox: ${req.session.sanbox_id}; Solve pow with: hashcash -mCb ${BITS} "${req.session.pow}"`);
});

app.post('/', (req, res, next) => {
  upload.single('file')(req, res, (err) => {
    if (err) {
      console.log(err);
      return res.status(400).send('File esiste o errore generico');
    }
    next();
  });
}, (req, res) => {
  res.set('Content-Type', 'text/plain');
  res.send('File uploaded');
});

//headless visit
app.get('/headless', async (req, res) => {
  if (!req.query.pow || !verify_pow(BITS, req.session.pow, req.query.pow)) {
    return res.status(400).send('Invalid pow');
  }
  req.session.pow = undefined;

  let invalid_protocol = ['javascript', 'data', 'file', 'ftp', 'about'];

  //take url from query
  let url = req.query.url;
  if (typeof url !== 'string') {
    return res.status(400).send('Invalid url');
  }

  if (!/^([a-z]+):\/\/([a-z]+(?:\.[a-z]+)?)$/.test(url)) {
    return res.status(400).send('Invalid url');
  }

  // no strange protocols
  for (let protocol of invalid_protocol) {
    if (url.startsWith(protocol)) {
      return res.status(400).send('Invalid url');
    }
  }

  let browser
  try {
    //start headless browser with puppeteer
    console.log(`[${req.session.sanbox_id}] Starting headless browser with `, url)
    browser = await puppeteer.launch({
      headless: 'new',
      executablePath: '/usr/bin/chromium',
      userDataDir: `/home/app/sandbox/${req.session.sanbox_id}/chromium`,
      args: ['--no-sandbox', '--disable-setuid-sandbox', '--profile-directory=Default']
    });
    let page = await browser.newPage();
    await page.goto('chrome://newtab');
    await new Promise(resolve => setTimeout(resolve, 10000));

    await page.evaluate((js_url) => {
      window.open(js_url);
    }, url);

    await new Promise(resolve => setTimeout(resolve, 10000));
  } catch (e) {
    console.log(e);
    return res.status(400).send('Headless error');
  } finally {
    if (browser) {
      try {
        await browser.close();
      } catch {
      }
    }
  }

  res.send('Headless visit!');
});

setInterval(() => {
  spawn('sh', ['-c', 'ps -eo etimes,pid,cmd | grep chromium | awk \'{if ($1 >= 120) print $2}\' | xargs kill -9']);
}, 120000);

app.listen(3000, () => {
  console.log('Server started on http://localhost:3000');
});

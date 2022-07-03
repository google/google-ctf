/**
 * Copyright 2022 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

const net = require('net');
const { connect } = require('http2');
const puppeteer = require('puppeteer');
const Deque = require("double-ended-queue");
const crypto = require("crypto").webcrypto;
const DOMAIN = process.env.DOMAIN || 'postviewer-web.2022.ctfcompetition.com';
if (DOMAIN == undefined) throw 'domain undefined'

const sleep = d => new Promise(r => setTimeout(r, d));

console.log(process.env);
const FLAG = process.env.FLAG || 'CTF{part1_part2_part3_part4_part5}';
const PAGE_URL = process.env.PAGE_URL || 'https://postviewer-web.2022.ctfcompetition.com';
const REGISTERED_DOMAIN = process.env.REGISTERED_DOMAIN;
const BLOCK_SUBORIGINS = process.env.BLOCK_SUBORIGINS == "1";
const BOT_TIMEOUT = process.env.BOT_TIMEOUT || 10000;
const MAX_BROWSERS = process.env.MAX_BROWSERS || 4;
const SECRET_TOKEN = process.env.SECRET_TOKEN || 's333cret_b00t_3ndop1nt'

/* Function copied from https://gist.github.com/chrisveness/43bcda93af9f646d083fad678071b90a */
async function aesGcmEncrypt(plaintext, password) {
  const textEnc = new TextEncoder();
  const pwHash = await crypto.subtle.digest('SHA-256', textEnc.encode(password));

  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ivStr = Array.from(iv).map(b => String.fromCharCode(b)).join('');

  const alg = { name: 'AES-GCM', iv: iv };

  const key = await crypto.subtle.importKey('raw', pwHash, alg, false, ['encrypt']);

  const ptUint8 = textEnc.encode(plaintext);
  const ctBuffer = await crypto.subtle.encrypt(alg, key, ptUint8);

  const ctArray = Array.from(new Uint8Array(ctBuffer));
  const ctStr = ctArray.map(byte => String.fromCharCode(byte)).join('');

  return btoa(ivStr + ctStr);
}

async function visitUrl(browser, data, socket) {
  const { url, timeout: bot_timeout } = data;
  return new Promise(async resolve => {

    const context = await browser.createIncognitoBrowserContext();
    const page = await context.newPage();

    await page.goto(PAGE_URL);
    await page.evaluate(ADD_NOTES_FUNC, await generateAdminFiles());

    await page.reload();
    await sleep(1000);
    const bodyHTML = await page.evaluate(() => document.documentElement.innerHTML);
    if (bodyHTML.includes('file-') && bodyHTML.includes('.txt')) {
      // socket_write(socket, 'Successfully logged in as admin.');
    } else {
      socket_write(socket, 'Something went wrong with logging as admin!');
      console.error('Something went wrong with logging as admin!');
      socket.destroy();
      return page.close();
    }

    setTimeout(async () => {
      await context.close();
      resolve(1);
      socket_write(socket, 'Timeout\n');
      try {
        socket.destroy();
      } catch (err) {
        console.log(`err: ${err}`);
      }
    }, bot_timeout);

    try{
      await page.goto(url);
    }catch(e){}
  });
}

class Queue {
  constructor(n_browsers) {
    this.browsers = [];
    this.queue = new Deque([]);
    this.addBrowsers(n_browsers);
    setInterval(() => { this.loop() }, 100);
  }
  async addBrowsers(N) {
    for (let i = 0; i < N; i++) {
      this.browsers[i] = {
        browser: await launchPup(i),
        free: true
      }
    }
  }

  add(socket, data) {
    this.loop();
    this.queue.push([socket, data]);
    console.log(`Adding ${data.url} to queue`);
    return this.queue.length;
  }

  loop() {
    for (let i = 0; i < this.browsers.length; i++) {
      if (this.queue.length === 0) break;
      if (this.browsers[i].free) {
        this.browsers[i].free = false;
        let [socket, data] = this.queue.shift();
        socket.state = 'LOADING';
        socket_write(socket, `Visiting: ${data.url}`);
        console.log(`Visiting ${data.url}`);
        visitUrl(this.browsers[i].browser, data, socket).finally(() => this.browsers[i].free = true);
      }
    }
  }

}

// will only be used if BLOCK_SUBORIGINS is enabled
const PAC_B64 = Buffer.from(`
function FindProxyForURL (url, host) {
  if (host == "${DOMAIN}") {
    return 'DIRECT';
  }
  if (host == "${REGISTERED_DOMAIN}" || dnsDomainIs(host, ".${REGISTERED_DOMAIN}")) {
    return 'PROXY 127.0.0.1:1';
  }
  return 'DIRECT';
}
`).toString('base64');

async function launchPup(i) {
  const r = i || Math.random() * 1e18;

  const puppeter_args = {
    headless: true,
    args: [
      `--user-data-dir=/tmp/chrome-userdata-${r}`,
      `--breakpad-dump-location=/tmp/chrome-crashes=${r}`,
      // '--block-new-web-contents=true',
      // '--unsafely-treat-insecure-origin-as-secure=http://postviewer:1337'
    ]
  };

  if (BLOCK_SUBORIGINS) {
    puppeter_args.headless = false;
    puppeter_args.args.push(
      '--proxy-pac-url=data:application/x-ns-proxy-autoconfig;base64,' + PAC_B64,
    )
  }
  return puppeteer.launch(puppeter_args);
}



const admin_file = (flag_cipher, password, i) => {
  return [
    `\
    Congratulations on fetching admin's file!

    The flag needs to be deciphered with a password that has been split into three
    random files. Because the password is random with each run, you will have to
    collect all three files. When you do so, just visit:
      ${PAGE_URL}/dec1pher

    File info:
    Cipher: ${flag_cipher}
    Password part [${i}/3]: ${password}

    The challenge is easily solvable under 5 seconds, but as a token of appreciation
    I set up a secret endpoint for you that have a limit of 20 seconds:
      ${PAGE_URL}/bot?s=${SECRET_TOKEN}
    `,
    `${crypto.randomUUID()}.txt`
  ]
}

function randString() {
  const randValues = new Uint32Array(3);
  crypto.getRandomValues(randValues);
  return randValues.reduce((a, b) => a + b.toString(36), '');
}

async function generateAdminFiles() {
  const password_parts = [randString(), randString(), randString()];
  const password = password_parts.join('');
  const flag_cipher = await aesGcmEncrypt(FLAG, password);
  const files = [];
  for (let i = 0; i < 3; i++) {
    files.push(admin_file(flag_cipher, password_parts[i], i + 1))
  }
  return files;
}


const ADD_NOTES_FUNC = async (files) => {
  const db = new DB();
  await db.clear();

  for (const [file, name] of files) {
    await db.addFile(new File([file], name, { type: 'text/plain' }));
  }
};

function verifyUrl(data) {
  let url = data.toString().trim();
  let timeout = BOT_TIMEOUT;

  try {
    let j = JSON.parse(url);
    url = j.url;
    timeout = j.timeout;
  } catch (e) { }

  if (typeof url !== "string" || (!url.startsWith('http://') && !url.startsWith('https://'))) {
    return false;
  }
  return { url, timeout }
}

function socket_write(socket, data) {
  try {
    socket.write(data + '\n');
  }
  catch (e) { }
};

function ask_for_url(socket) {
  socket.state = 'URL';
  socket_write(socket, 'Please send me a URL to open.\n');
}


(async function () {
  const queue = new Queue(MAX_BROWSERS);

  async function load_url(socket, data) {
    data = verifyUrl(data);
    if (data === false) {
      socket.state = 'ERROR';
      socket_write(socket, 'Invalid scheme (http/https only).\n');
      socket.destroy();
      return;
    }

    socket.state = 'WAITING';

    const pos = queue.add(socket, data);
    socket_write(socket, `Task scheduled, position in the queue: ${pos}`);
  }

  var server = net.createServer();
  server.listen(1338);
  console.log('listening on port 1338');

  server.on('connection', socket => {
    socket.on('data', data => {
      try {
        if (socket.state == 'URL') {
          load_url(socket, data);
        }
      } catch (err) {
        console.log(`err: ${err}`);
      }
    });

    socket.on('error', e => {
      console.error(e);
    });

    try {
      ask_for_url(socket);
    } catch (err) {
      console.log(`err: ${err}`);
    }
  });
})();


/**
 * Copyright 2023 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

const puppeteer = require('puppeteer');
const net = require('net');

const BOT_TIMEOUT = process.env.BOT_TIMEOUT || 7000;
const FLAG = process.env.FLAG || 'CTF{dummy_flag}';
const PAGE_URL = process.env.PAGE_URL || 'https://postviewer2-web.2023.ctfcompetition.com/';

const sleep = d => new Promise(r => setTimeout(r, d));

const puppeter_args = {
  headless: 'old',
  args: [
    '--user-data-dir=/tmp/chrome-userdata',
    '--breakpad-dump-location=/tmp/chrome-crashes',
    '--block-new-web-contents',
    '--disable-popup-blocking=false',
    '--enable-features=StrictOriginIsolation'
  ]
};

async function visitUrl(context, data, sendToPlayer) {
  const { url, timeout: bot_timeout } = data;
  return new Promise(async resolve => {

    const page = await context.newPage();

    await page.goto(PAGE_URL);

    const pageStr = await page.evaluate(() => document.documentElement.innerHTML);

    if(!pageStr.includes('Postviewer v2')){
      const msg = 'Error: Failed to load challenge page.';
      console.error(`${msg}\nPage:${pageStr}`);
      resolve(msg);
      return;
    }

    sendToPlayer("Adding admin's flag.");
    await page.evaluate((flag) => {
      const db = new DB();
      db.clear();
      const blob = new Blob([flag], { type: 'text/plain' });
      db.addFile(new File([blob], `flag.txt`, { type: blob.type }));
    }, FLAG);
    
    await page.reload();
    await sleep(1000);

    const bodyHTML = await page.evaluate(() => document.documentElement.innerHTML);
  
    if(!bodyHTML.includes('file-') && bodyHTML.includes('.txt')) {
      const msg = 'Error: Something went wrong while adding the flag.';
      resolve(msg);
      console.error(`${msg}\nPage:${bodyHTML}`);
      return;
    }

    sendToPlayer('Successfully added the flag.');
    sendToPlayer(`Visiting ${url}`);
    await page.close();
    
    const playerPage = await context.newPage();
    setTimeout(async () => {
      const origin = await playerPage.evaluate(() => document.location.href);
      resolve(`Timeout: ${origin}`);
    }, bot_timeout);
    try{
      await playerPage.goto(url);
    }catch(e){};
  });
}

function verifyUrl(data) {
  let url = data.toString().trim();
  let timeout = BOT_TIMEOUT;

  try {
    let j = JSON.parse(url);
    url = j.url;
    timeout = j.timeout;
  } catch (e) { }

  if (typeof url !== 'string' || (!url.startsWith('http://') && !url.startsWith('https://'))) {
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

function end(socket){
  socket.end();
}

function ask_for_url(socket) {
  socket.state = 'URL';
  socket_write(socket, 'Please send me a URL to open.\n');
}


(async function () {
  const browser = await puppeteer.launch(puppeter_args);


  async function load_url(socket, data) {
    data = verifyUrl(data);
    if (data === false) {
      socket.state = 'ERROR';
      socket_write(socket, 'Invalid scheme (http/https only).\n');
      end(socket);
      return;
    }

    socket.state = 'LOADING';
    const context = await browser.createIncognitoBrowserContext();
    socket_write(socket, `Visiting application website.`);

    const sendToPlayer = msg => socket_write(socket, msg);
    try{
      const finalResponse = await visitUrl(context, data, sendToPlayer);
      sendToPlayer(finalResponse);
    }catch(e){
      sendToPlayer('Error: something went wrong when visiting player URL.');
      console.error(e);
    }finally{
      context.close();
    }    
    end(socket);
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
        console.error(`err: ${err}`);
      }
    });

    socket.on('error', e => {
      console.error(e);
    });

    try {
      ask_for_url(socket);
    } catch (err) {
      console.error(`err: ${err}`);
    }
  });
})();


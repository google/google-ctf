const puppeteer = require('puppeteer');
const process = require('process');
const fs = require('fs');
const net = require('net');
const pow = require('proof-of-work');
const crypto = require("crypto");

const pow_difficulty = 22;

let verifier;
if (pow_difficulty) {
  verifier = new pow.Verifier({
    size: 1024,
    n: 16,
    complexity: pow_difficulty,
    prefix: crypto.randomBytes(2),
    validity: 180000
  });
  setInterval(() => {
    verifier.reset();
  }, 180000);
}


(async function(){
  const browser = await puppeteer.launch();

  function ask_for_url(socket) {
      socket.state = 'URL';
      socket.write('Please send me a URL to open.\n');
  }

  function ask_for_pow(socket) {
    if (pow_difficulty) {
      socket.state = 'POW';
      socket.write(`Please solve a proof-of work with difficulty ${pow_difficulty} and prefix ${verifier.prefix.toString('hex')} using https://www.npmjs.com/package/proof-of-work\n`);
    } else {
      socket.write('Proof-of-work disabled.\n');
      ask_for_url(socket);
    }
  }

  function validate_pow(socket, data) {
    if (verifier.check(Buffer.from(data.toString().trim(), 'hex'))) {
      socket.write('Proof-of-work verified.\n');
      ask_for_url(socket);
    } else {
      socket.state = 'ERROR';
      socket.write('Proof-of-work invalid.\n');
      socket.destroy();
    }
  }

  async function load_url(socket, data) {
    let url = data.toString().trim();
    console.log(`checking url: ${url}`);
    if (!url.startsWith('http://') && !url.startsWith('https://')) {
      socket.state = 'ERROR';
      socket.write('Invalid scheme (http/https only).\n');
      socket.destroy();
      return;
    }
    socket.state = 'LOADED';
    let cookie = JSON.parse(fs.readFileSync('/cookie'));

    const page = await browser.newPage();
    await page.setCookie(cookie);
    socket.write(`Loading page ${url}.\n`);
    await page.goto(url);
    setTimeout(()=>{
      try {
        page.close();
        socket.write('timeout\n');
        socket.destroy();
      } catch (err) {
        console.log(`err: ${err}`);
      }
      }, 60000);
  }

  var server = net.createServer();
  server.listen(1337);
  console.log('liistening on port 1337');

  server.on('connection', socket=>{
    socket.captcha = 'foo';

    socket.on('data', data=>{
      try {
        if (socket.state == 'POW') {
          validate_pow(socket, data);
        } else if (socket.state == 'URL') {
          load_url(socket, data);
        }
      } catch (err) {
        console.log(`err: ${err}`);
      }
    });

    try {
      ask_for_pow(socket);
    } catch (err) {
      console.log(`err: ${err}`);
    }
  });
})();


const puppeteer = require('puppeteer');
const fs = require('fs');
const net = require('net');

const DOMAIN = process.env.DOMAIN;
if (DOMAIN == undefined) throw 'domain undefined'
const REGISTERED_DOMAIN = process.env.REGISTERED_DOMAIN;
const BLOCK_SUBORIGINS = process.env.BLOCK_SUBORIGINS == "1";

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
const puppeter_args = {};
if (BLOCK_SUBORIGINS) {
  puppeter_args.headless = false;
  puppeter_args.args = [
    '--user-data-dir=/tmp/chrome-userdata',
    '--breakpad-dump-location=/tmp/chrome-crashes',
    '--proxy-pac-url=data:application/x-ns-proxy-autoconfig;base64,'+PAC_B64,
  ];
}

(async function(){
  const browser = await puppeteer.launch(puppeter_args);

  function ask_for_url(socket) {
      socket.state = 'URL';
      socket.write('Please send me a URL to open.\n');
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
    let cookie = JSON.parse(fs.readFileSync('/home/user/cookie'));

    const context = await browser.createIncognitoBrowserContext();
    const page = await context.newPage();
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
  server.listen(1338);
  console.log('listening on port 1338');

  server.on('connection', socket=>{
    socket.on('data', data=>{
      try {
        if (socket.state == 'URL') {
          load_url(socket, data);
        }
      } catch (err) {
        console.log(`err: ${err}`);
      }
    });

    try {
      ask_for_url(socket);
    } catch (err) {
      console.log(`err: ${err}`);
    }
  });
})();


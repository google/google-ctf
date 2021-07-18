// Copyright 2021 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Author: Kegan Thorrez

const puppeteer = require('puppeteer');
const fs = require('fs');
const net = require('net');
const request = require('request');

(async function(){
  let browser;

  try {
    browser = await puppeteer.launch();

    const cert = fs.readFileSync('/home/user/admin_client.crt.pem');
    const key = fs.readFileSync('/home/user/admin_client.key.pem');

    async function load_url(socket, data) {
      let url = data.toString().trim();
      console.log(`Checking url: ${url}`);

      // While the challenge only suports https:// , the healthchecker uses
      // http:// . The central server limits the scheme (and host) before sending
      // the url to the bot.
      if (!url.startsWith('http://') && !url.startsWith('https://')) {
        socket.state = 'ERROR';
        console.log('Invalid scheme (http/https only)');
        socket.end()
        socket.destroy();
        return;
      }
      socket.state = 'LOADED';

      const context = await browser.createIncognitoBrowserContext();
      const page = await context.newPage();
      socket.write('Loading page\n');
      socket.end()
      socket.destroy();
      await page.setRequestInterception(true);

      // https://github.com/puppeteer/puppeteer/issues/1319#issuecomment-371503788
      page.on('request', inReq => {
        console.log('the top of page.on request');
        const options = {
          uri: inReq.url(),
          method: inReq.method(),
          headers: inReq.headers(),
          body: inReq.postData(),
          requestCert: true,
          agent: false,
          cert: cert,
          key: key
        };
        request(options, function(err, resp, body) {
          console.log('in request callback');
          if (err) {
            console.error(`Unable to request ${options.uri}`, err);
            return inReq.abort('connectionrefused');
          }
          console.log('request callback had no error');

          let bodyToLog = body;
          if (bodyToLog) {
            bodyToLog = bodyToLog.substring(0, 256);
          }
          console.log(`bodyToLog: ${bodyToLog}`);

          inReq.respond({
            status: resp.statusCode,
            contentType: resp.headers['content-type'],
            headers: resp.headers,
            body: body
          });
          console.log('did final respond');
        });
        console.log('the bottom of page.on request');
      });

      try {
        await page.goto(url);
        console.log('going to sleep');
        await new Promise(resolve => setTimeout(resolve, 5000));
        console.log('sleep is done');
      } catch (err) {
        console.log(`err in page.goto: ${err}`);
      }
      console.log('going to close the page');
      await page.close();
      console.log('going to close the context');
      await context.close();
      console.log('closed the context');
    }

    const server = net.createServer();
    server.listen(1337);
    console.log('listening on port 1337');

    server.on('connection', socket => {
      console.log('the top of socket.on connection');
      socket.on('data', data => {
        console.log('the top of socket.on data');
        try {
          if (socket.state == 'URL') {
            console.log('going to call load_url');
            load_url(socket, data);
            console.log('called load_url');
          }
        } catch (err) {
          console.log(`err calling load_url: ${err}`);
        }
      });

      socket.state = 'URL';
      console.log('the bottom of socket.on connection');
    });

  } catch (err) {
    console.log(`err during startup: ${err}`);
    if (browser) {
      console.log('closing the browser');
      await browser.close();
      console.log('closed the browser');
    }
  }
})();

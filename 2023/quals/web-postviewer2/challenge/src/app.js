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

const express = require('express');
const path = require('path');
const net = require('net');
const Recaptcha = require('express-recaptcha').RecaptchaV3
const vhost = require('vhost');

const XSSBOT_DOMAIN = process.env.XSSBOT_DOMAIN || 'postviewer2-bot';
const XSSBOT_PORT = process.env.XSSBOT_PORT || 1337;
const NO_CAPTCHA =  process.env.NO_CAPTCHA || "QQIoMKQeeru6xUhu";
const CAPTCHA_SITE_KEY = process.env.CAPTCHA_SITE_KEY || "6LePlW8mAAAAACxrLLlBsTPG4mJEP4LB7owGXsUh";
const CAPTCHA_SECRET_KEY = process.env.CAPTCHA_SECRET_KEY || "6LePlW8mAAAAALVuekBuUaePCLBHKnYritAm4XSF";
const DOMAIN = process.env.DOMAIN || 'localhost:1337';
// const DOMAIN = 'localhost:1337';
const PORT = process.env.PORT || 1337;

const sec_headers = (req, res, next) => {
  res.set('Cache-control', 'public, max-age=300');
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('Cross-Origin-Opener-Policy', 'same-origin');
  res.setHeader('Referrer-Policy', 'no-referrer')
  return next();
}

const app = express();
const sandbox = express();
const mainapp = express();
const bot = express();

sandbox.use(sec_headers);
sandbox.use((req, res, next) => {
  res.set('Content-Security-Policy', 'frame-src blob:');
  return next();
});

sandbox.use('/', express.static('sandbox'));

const DOMAIN_NO_PORT = DOMAIN.split(':')[0];

app.use(vhost(`sbx-*.${DOMAIN_NO_PORT}`, sandbox));
app.use(vhost(DOMAIN_NO_PORT, mainapp));
app.use(vhost(`bot.${DOMAIN_NO_PORT}`, bot));
app.use(sec_headers);

app.get('*', (req, res) => {
  res.set('X-Frame-Options', 'DENY');
  res.set('Content-Security-Policy', "default-src 'none'");
  res.send('Not found');
})

mainapp.use(sec_headers);
bot.use(sec_headers);


mainapp.use((req, res, next) =>{
  res.locals.base = `//${DOMAIN}/`;
  res.locals.bot = `//bot.${DOMAIN}/bot`
  next();
})

bot.use((req, res, next) => {
  res.locals.base = `//${DOMAIN}/`;
  res.locals.bot = `//bot.${DOMAIN}/bot`
  next();
})
bot.use(express.urlencoded({ extended: false }));
bot.use(express.json());

mainapp.use('/', (req, res, next) => {
  res.set('Content-Security-Policy', `frame-ancestors *.${DOMAIN}; frame-src *.${DOMAIN}`);
  next();
});

mainapp.set('view engine', 'ejs');
mainapp.use('/static/', express.static('static'));

bot.set('view engine', 'ejs');

console.log(process.env);
const recaptcha = new Recaptcha(CAPTCHA_SITE_KEY, CAPTCHA_SECRET_KEY, { hl: 'en', callback: 'captcha_cb' });

mainapp.get('/', (req, res) => {
  res.render('index');
});

bot.get('/bot', recaptcha.middleware.render, (req, res) => {
  // return res.send("[internal testing]: Bot coming soon, please await the announement.")
  res.render('bot', { captcha: res.recaptcha });
});

bot.post('/bot', recaptcha.middleware.verify, async (req, res) => {
  res.setHeader('Content-type', 'text/plain');

  const url = req.body.url;
  if (typeof url !== 'string') {
    return res.send('Invalid type for URL');
  }

  if(req.headers['x-admin-secret'] !== NO_CAPTCHA){
    if (req.recaptcha.error) {
      console.error(req.recaptcha.error);
      res.send('captcha error');
      return;
    }

    if (url.length > 256) {
      return res.send('Too long URL!')
    }
    if (!/^https?:\/\//.test(url)) {
      return res.send('The URL needs to start with https?://');
    }
  }


  const timeout = 7000;
  const client = net.Socket();
  client.connect(XSSBOT_PORT, XSSBOT_DOMAIN);
  await new Promise(resolve => {
    let scheduled = false;
    client.on('data', data => {
      let msg = data.toString();
      if (msg.includes("Please send me")) {
        client.write(JSON.stringify({
          url,
          timeout
        }) + '\n');
        console.log(`sending to bot: ${url}`);
      }else{
        res.write(msg + '\n')
        if(/(Timeout|Error): /.test(msg)){
          res.write('Done.\n')
          res.end();
        }
      }
    });
  });
});


app.listen(PORT, () => {
  console.log(`App listening on port ${PORT}`);
  console.log('Press Ctrl+C to quit.');
});

module.exports = app;

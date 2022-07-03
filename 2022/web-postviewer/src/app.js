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

const express = require('express');
const path = require('path');
const net = require('net');
const Recaptcha = require('express-recaptcha').RecaptchaV3

const app = express();

app.set('view engine', 'ejs');
app.use('/static/', express.static('static'));

const XSSBOT_DOMAIN = process.env.XSSBOT_DOMAIN || 'postviewer-bot';
const XSSBOT_PORT = process.env.XSSBOT_PORT || 1337;
const SECRET_TOKEN = "s333cret_b00t_3ndop1nt";
const CAPTCHA_SITE_KEY = process.env.CAPTCHA_SITE_KEY || "a";
const CAPTCHA_SECRET_KEY = process.env.CAPTCHA_SECRET_KEY || "b";

console.log(process.env);
const recaptcha = new Recaptcha(CAPTCHA_SITE_KEY, CAPTCHA_SECRET_KEY, { hl: 'en', callback: 'captcha_cb' });

const sec_headers = (req, res, next) => {
  res.set('Cache-control', 'public, max-age=300');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('X-Content-Type-Options', 'nosniff');
  return next();
}

app.use(express.urlencoded({ extended: false }));
app.use(sec_headers);

app.get('/', (req, res) => {
  res.render('index');
});

app.get('/bot', recaptcha.middleware.render, (req, res) => {
  res.render('bot', { captcha: res.recaptcha });
});

app.get('/s333cret_b00t_3ndop1nt', (req, res) => {
  res.render('bot_secret');
});


app.get('/dec1pher', (req, res) => {
  res.render('decipher');
});

app.post('/bot', recaptcha.middleware.verify, async (req, res) => {
  res.setHeader('Content-type', 'text/plain');

  if (req.recaptcha.error) {
    res.send('captcha error');
    return;
  }
  const url = req.body.url;
  if (typeof url !== 'string') {
    return res.send('Invalid type for URL');
  }
  if (url.length > 256) {
    return res.send('Too long URL!')
  }
  if (!/^https?:\/\//.test(url)) {
    return res.send('The URL needs to start with https?://');
  }


  const timeout = req.query.s === SECRET_TOKEN ? 20000 : 7000;
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
      }
      if(msg.includes("position in the queue")){
        scheduled = true;
        res.send(msg);
        client.destroy();
        resolve(1);
      }
    });

    setTimeout(()=>{
      if(!scheduled){
        res.send("Something wrong with the bot, please reach out to admins.");
        console.error("Bot is not responsive.");
        resolve(-1);
      }
    }, 5000);

  });
});

const PORT = process.env.PORT || 1337;

app.listen(PORT, () => {
  console.log(`App listening on port ${PORT}`);
  console.log('Press Ctrl+C to quit.');
});

module.exports = app;

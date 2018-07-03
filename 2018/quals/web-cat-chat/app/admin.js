// Copyright 2018 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

const fs = require('fs');
const https = require('https');
const querystring = require('querystring');
const pubsub = require('@google-cloud/pubsub')();

var flag = 'CTF{L0LC47S_43V3R}';
// Add recaptcha secret here, and add ID in index.html
var recaptcha_secret = '';

module.exports.report = function report(captcha, ip, room) {
  return new Promise(function(resolve, reject) {
    console.log('Verifying reporter:', captcha, ip, room)
    var payload = querystring.stringify({
      secret: recaptcha_secret,
      response: captcha,
      remoteip: ip,
    });
    var req = https.request({
      host: 'www.google.com',
      path: '/recaptcha/api/siteverify',
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        'Content-Length': Buffer.byteLength(payload)
      },
    }, function(res) {
      var body = '';
      res.on('data', (chunk) => body += chunk);
      res.on('end', function() {
        res = JSON.parse(body);
        console.log('Verification response:', res);
        if (res.action == 'report' && res.score >= 0.2) {
          pubsub.topic('xss').publisher().publish(Buffer.from(JSON.stringify({
            url: room,
            service: 'catchat',
          }))).then(function() {
            resolve({type: 'msg', name: 'reporting_service', msg: 'admin have been notified'});
          }, function(err) {
            resolve({type: "error"});
            console.log('Error when notifying admin:', err);
          });
        } else {
          resolve({type: "error", error: `Sorry, it seems like you're a bot and not a hooman, so we're not calling the admin :/`});
        }
      });
    });
    req.end(payload);
    req.on('error', function(err) {
      console.log('reCAPTCHA request error:', err);
      resolve({type: "error"});
    });
  });
}

var adminJavascript = `;localStorage.name = 'admin';setTimeout(cleanupRoomFullOfBadPeople, 1000);`;

module.exports.middleware = function(req, res, next) {
  req.admin = (req.cookies.flag == flag);
  if (req.admin && req.url.endsWith('/catchat.js')) {
    console.log('Admin in da house!');
    fs.readFile(__dirname + '/static/catchat.js', 'utf-8', function(err, js) {
      res.end(js + adminJavascript);
    });
  } else {
    next();
  }
}

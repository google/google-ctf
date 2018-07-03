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

const http = require('http');
const express = require('express');
const cookieParser = require('cookie-parser')
const uuidv4 = require('uuid/v4');
const SSEClient = require('sse').Client;
const admin = require('./admin');
const pubsub = require('@google-cloud/pubsub')();

const app = express();
app.set('etag', false);
app.use(cookieParser());

// Check if user is admin based on the 'flag' cookie, and set the 'admin' flag on the request object
app.use(admin.middleware);

// Check if banned
app.use(function(req, res, next) {
  if (req.cookies.banned) {
    res.sendStatus(403);
    res.end();
  } else {
    next();
  }
});

// Opening redirect and room index
app.get('/', (req, res) => res.redirect(`/room/${uuidv4()}/`));
let roomPath = '/room/:room([0-9a-f-]{36})';
app.get(roomPath + '/', function(req, res) {
  res.sendFile(__dirname + '/static/index.html', {
    headers: {
      'Content-Security-Policy': [
        'default-src \'self\'',
        'style-src \'unsafe-inline\' \'self\'',
        'script-src \'self\' https://www.google.com/recaptcha/ https://www.gstatic.com/recaptcha/',
        'frame-src \'self\' https://www.google.com/recaptcha/',
      ].join('; ')
    },
  });
});

// Process incoming messages
app.all(roomPath + '/send', async function(req, res) {
  let room = req.params.room, {msg, name} = req.query, response = {}, arg;
  console.log(`${room} <-- (${name}):`, msg)
  if (!(req.headers.referer || '').replace(/^https?:\/\//, '').startsWith(req.headers.host)) {
    response = {type: "error", error: 'CSRF protection error'};
  } else if (msg[0] != '/') {
    broadcast(room, {type: 'msg', name, msg});
  } else {
    switch (msg.match(/^\/[^ ]*/)[0]) {
      case '/name':
        if (!(arg = msg.match(/\/name (.+)/))) break;
        response = {type: 'rename', name: arg[1]};
        broadcast(room, {type: 'name', name: arg[1], old: name});
      case '/ban':
        if (!(arg = msg.match(/\/ban (.+)/))) break;
        if (!req.admin) break;
        broadcast(room, {type: 'ban', name: arg[1]});
      case '/secret':
        if (!(arg = msg.match(/\/secret (.+)/))) break;
        res.setHeader('Set-Cookie', 'flag=' + arg[1] + '; Path=/; Max-Age=31536000');
        response = {type: 'secret'};
      case '/report':
        if (!(arg = msg.match(/\/report (.+)/))) break;
        var ip = req.headers['x-forwarded-for'];
        ip = ip ? ip.split(',')[0] : req.connection.remoteAddress;
        response = await admin.report(arg[1], ip, `https://${req.headers.host}/room/${room}/`);
    }
  }
  console.log(`${room} --> (${name}):`, response)
  res.json(response);
  res.status(200);
  res.end();
});

// Process room broadcast messages
const rooms = new Map();

app.get(roomPath + '/receive', function(req, res) {
  res.setHeader('X-Accel-Buffering', 'no');
  let channel = new SSEClient(req, res);
  channel.initialize();
  let roomName = req.params.room;
  let room = rooms.get(roomName) || new Set();
  rooms.set(roomName, room.add(channel))
  req.once('close', () => { room.size > 1 ? room.delete(channel) : rooms.delete(roomName) });
});

// Broadcast to all instances using Cloud Pub/Sub. For local testing, it's easy
// to skip by commenting it out and patching the broadcast fn below.
var publisher;
pubsub.createTopic('catchat', function() {
  var topic = pubsub.topic('catchat');
  publisher = topic.publisher();
  topic.createSubscription('catchat-' + uuidv4(), {ackDeadlineSeconds: 10}).then(function(data) {
    data[0].on('message', function(msg) {
      msg.ack();
      var room = msg.attributes.room;
      if (!rooms.has(room)) return;
      var msg = msg.data.toString('utf-8');
      console.log(`${room} ^^^`, msg)
      for (let channel of rooms.get(room)) channel.send(msg);
    });
  });
});

function broadcast(room, msg) {
  // for (let channel of (rooms.get(room) || [])) channel.send(JSON.stringify(msg)); // Local broadcast only
  publisher.publish(Buffer.from(JSON.stringify(msg)), {room: room}); // Pub/Sub broadcast
}

// Static files
app.get('/server.js', (req, res) => res.sendFile(__filename));
app.use(express.static(__dirname + '/static/', {fallthrough: false}));

app.listen(8080);

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

// Set name
let color = ['brown', 'black', 'yellow', 'white', 'grey', 'red'][Math.floor(Math.random()*6)];
let breed = ['ragamuffin', 'persian', 'siamese', 'siberian', 'birman', 'bombay', 'ragdoll'][Math.floor(Math.random()*7)];
if (!localStorage.name) localStorage.name = color + '_' + breed;

// Utility functions
let cookie = (name) => (document.cookie.match(new RegExp(`(?:^|; )${name}=(.*?)(?:$|;)`)) || [])[1];
let esc = (str) => str.replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&apos;');

// Sending messages
let send = (msg) => fetch(`send?name=${encodeURIComponent(localStorage.name)}&msg=${encodeURIComponent(msg)}`,
    {credentials: 'include'}).then((res) => res.json()).then(handle);
let display = (line) => conversation.insertAdjacentHTML('beforeend', `<p>${line}</p>`);
let recaptcha_id = '6LeB410UAAAAAGkmQanWeqOdR6TACZTVypEEXHcu';
window.addEventListener('load', function() {
  messagebox.addEventListener('keydown', function(event) {
    if (event.keyCode == 13 && messagebox.value != '') {
      if (messagebox.value == '/report') {
        grecaptcha.execute(recaptcha_id, {action: 'report'}).then((token) => send('/report ' + token));
      } else {
        send(messagebox.value);
      }
      messagebox.value = '';
    }
  });
  send('Hi all');
});

// Receiving messages
function handle(data) {
  ({
    undefined(data) {},
    error(data) { display(`Something went wrong :/ Check the console for error message.`); console.error(data); },
    name(data) { display(`${esc(data.old)} is now known as ${esc(data.name)}`); },
    rename(data) { localStorage.name = data.name; },
    secret(data) { display(`Successfully changed secret to <span data-secret="${esc(cookie('flag'))}">*****</span>`); },
    msg(data) {
      let you = (data.name == localStorage.name) ? ' (you)' : '';
      if (!you && data.msg == 'Hi all') send('Hi');
      display(`<span data-name="${esc(data.name)}">${esc(data.name)}${you}</span>: <span>${esc(data.msg)}</span>`);
    },
    ban(data) {
      if (data.name == localStorage.name) {
        document.cookie = 'banned=1; Path=/';
        sse.close();
        display(`You have been banned and from now on won't be able to receive and send messages.`);
      } else {
        display(`${esc(data.name)} was banned.<style>span[data-name^=${esc(data.name)}] { color: red; }</style>`);
      }
    },
  })[data.type](data);
}
let sse = new EventSource("receive");
sse.onmessage = (msg) => handle(JSON.parse(msg.data));

// Say goodbye
window.addEventListener('unload', () => navigator.sendBeacon(`send?name=${encodeURIComponent(localStorage.name)}&msg=Bye`));

// Admin helper function. Invoke this to automate banning people in a misbehaving room.
// Note: the admin will already have their secret set in the cookie (it's a cookie with long expiration),
// so no need to deal with /secret and such when joining a room.
function cleanupRoomFullOfBadPeople() {
  send(`I've been notified that someone has brought up a forbidden topic. I will ruthlessly ban anyone who mentions d*gs going forward. Please just stop and start talking about cats for d*g's sake.`);
  last = conversation.lastElementChild;
  setInterval(function() {
    var p;
    while (p = last.nextElementSibling) {
      last = p;
      if (p.tagName != 'P' || p.children.length < 2) continue;
      var name = p.children[0].innerText;
      var msg = p.children[1].innerText;
      if (msg.match(/dog/i)) {
        send(`/ban ${name}`);
        send(`As I said, d*g talk will not be tolerated.`);
      }
    }
  }, 1000);
}

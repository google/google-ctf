// Copyright 2024 Google LLC
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
const puppeteer = require("puppeteer"); // ^22.10.0
const net = require("net");
const Deque = require("double-ended-queue");
const { visitUrl, args } = require("./visit.js");

const BOT_TIMEOUT = parseInt(process.env.BOT_TIMEOUT) || 10_000;
const MAX_BROWSERS = parseInt(process.env.MAX_BROWSERS) || 5;

async function launchPup(i) {
  const r = i || Math.random() * 1e18;

  const puppeter_args = {
    headless: args.headless,
    args: [
      `--user-data-dir=/tmp/chrome-userdata-${r}`,
      `--breakpad-dump-location=/tmp/chrome-crashes=${r}`,
      ...args.args,
    ],
  };

  return puppeteer.launch(puppeter_args);
}

class Queue {
  constructor(n_browsers) {
    this.browsers = [];
    this.queue = new Deque([]);
    this.addBrowsers(n_browsers);
    setInterval(() => {
      this.loop();
    }, 100);
  }
  async addBrowser(i) {
    const browser = await launchPup(i);
    browser.on("disconnected", async () => {
      console.error("Browser disconnected, spawning a new one");
      this.browsers[i].free = false;
      this.addBrowser(i);
    });
    this.browsers[i] = {
      browser,
      free: true,
    };
  }
  async addBrowsers(N) {
    for (let i = 0; i < N; i++) {
      this.addBrowser(i);
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
        const sendToPlayer = (msg) => socket_write(socket, msg);
        this.browsers[i].free = false;
        let [socket, { url, timeout }] = this.queue.shift();
        console.log(`Visiting: ${url}`);
        socket.state = "LOADING";
        sendToPlayer(`Task started.`);

        const bro = this.browsers[i];
        const _ctx = bro.browser.createBrowserContext();
        let closed = false;
        const closeAll = async () => {
          if (closed) return;
          closed = true;
          end(socket);
          bro.browser.close().catch(() => {});
        };
        setTimeout(async () => {
          if (closed) return;
          sendToPlayer("Timed out");
          closeAll();
        }, timeout);

        visitUrl(_ctx, url, sendToPlayer).catch((e) => {
          if (closed) return;
          console.error(e);
          sendToPlayer(`Error while visiting ${url}`);
          closeAll();
        });
      }
    }
  }
}

function verifyUrl(data) {
  let url = data.toString().trim();
  let timeout = BOT_TIMEOUT;

  try {
    let j = JSON.parse(url);
    url = j.url;
    timeout = j.timeout;
  } catch (e) {}

  if (
    typeof url !== "string" ||
    (!url.startsWith("http://") && !url.startsWith("https://"))
  ) {
    return false;
  }
  return { url, timeout };
}

function socket_write(socket, data) {
  try {
    socket.write(data + "\n");
  } catch (e) {}
}

function end(socket) {
  socket.end();
}

function ask_for_url(socket) {
  socket.state = "URL";
  socket_write(socket, "Please send me a URL to open.\n");
}

(async function () {
  const queue = new Queue(MAX_BROWSERS);

  async function load_url(socket, data) {
    data = verifyUrl(data);
    if (data === false) {
      socket.state = "ERROR";
      socket_write(socket, "Invalid scheme (http/https only).\n");
      end(socket);
      return;
    }

    socket.state = "WAITING";

    const pos = queue.add(socket, data);
    socket_write(socket, `Task scheduled, position in the queue: ${pos}`);
  }

  var server = net.createServer();
  server.listen(1338);
  console.log("listening on port 1338");

  server.on("connection", (socket) => {
    socket.on("data", (data) => {
      try {
        if (socket.state == "URL") {
          load_url(socket, data);
        }
      } catch (err) {
        console.error(`err: ${err}`);
      }
    });

    socket.on("error", (e) => {
      console.error(e);
    });

    try {
      ask_for_url(socket);
    } catch (err) {
      console.error(`err: ${err}`);
    }
  });
})();

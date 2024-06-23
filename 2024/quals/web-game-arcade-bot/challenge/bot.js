/**
 * Copyright 2024 Google LLC
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

const puppeteer = require("puppeteer");
const net = require("net");

const BOT_TIMEOUT = process.env.BOT_TIMEOUT || 10 * 1000;
const PAGE_URL =
  process.env.PAGE_URL || "https://game-arcade-web.2024.ctfcompetition.com/";
const FLAG = process.env.FLAG || "ctf{dummy_flag}";

const sleep = (d) => new Promise((resolve) => setTimeout(resolve, d));
(async function () {
  const browser = await puppeteer.launch({
    product: "firefox", // npx puppeteer browsers install firefox@stable
    protocol: "webDriverBiDi",
    userDataDir: "/tmp/mozilla-userdata",
  });

  function ask_for_url(socket) {
    socket.state = "URL";
    socket.write("Please send me a URL to open.\n");
  }

  function end(socket) {
    try {
      socket.end();
    } catch (e) {}
  }

  function write_socket(socket, data) {
    try {
      socket.write(data + "\n");
    } catch (e) {}
  }

  async function load_url(socket, data) {
    let url = data.toString().trim();
    console.log(`checking url: ${url}`);
    if (!url.startsWith("http://") && !url.startsWith("https://")) {
      socket.state = "ERROR";
      write_socket(socket, "Invalid scheme (http/https only).");
      end(socket);
      return;
    }
    socket.state = "LOADED";

    const context = await browser.createBrowserContext();

    function sendToPlayer(msg) {
      write_socket(socket, msg);
    }

    try {
      const page = await context.newPage();

      await page.goto(PAGE_URL, { timeout: 2000 });
      const pageStr = await page.evaluate(
        () => document.documentElement.innerHTML
      );

      if (!pageStr.includes("Game Arcade")) {
        const msg =
          "Error: Failed to load challenge page. Please contact admins.";
        console.error(`Page:${pageStr}`);
        sendToPlayer(msg);
        throw new Error(msg);
      }

      sendToPlayer("Adming's playing Guess the Password.");

      await page.waitForSelector("#file-0");
      page.click("#file-1");

      const popup = await context
        .waitForTarget((target) => {
          return target.url().startsWith("blob:");
        })
        .then((e) => e.page());

      await popup.waitForSelector("#guessInp");
      await popup.type("#passwordInp", FLAG);
      await popup.click("#changePwdBtn");
      await sleep(500);

      await popup.close();
      await page.close();
      await sleep(500);

      sendToPlayer(`Visiting ${url}`);
      let playerPage = null;
      setTimeout(() => {
        try {
          sendToPlayer(`Timeout [${playerPage.url()}]`);
          context.close().catch((e) => {
            console.error(e);
          });
          end(socket);
        } catch (err) {
          console.log(`err: ${err}`);
        }
      }, BOT_TIMEOUT);

      try {
        playerPage = await context.newPage();
        playerPage.goto(url).catch((e) => {
          console.error(e);
        });
      } catch (e) {
        console.error(e);
      }
    } catch (e) {
      context.close();
    }
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

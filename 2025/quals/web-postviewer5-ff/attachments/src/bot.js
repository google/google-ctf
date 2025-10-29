/**
 * Copyright 2025 Google LLC
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

const puppeteer = require("puppeteer"); // ^22.10.0

const FLAG = process.env.FLAG || "CTF{dummy_flag}";
const PAGE_URL = "http://localhost:1338";

console.log(FLAG)

const sleep = (d) => new Promise((r) => setTimeout(r, d));

let browser;

const visit = async (url, log = () => { }) => {
  if (browser) {
    await browser.close();
    await sleep(2000);
    log("Terminated ongoing job.");
  }
  try {
    browser = await puppeteer.launch({
      browser: "firefox",
      headless: false,
      userDataDir: '/tmp/firefox-userdata',
      pipe: true
    });

    const ctx = await browser.createBrowserContext();

    log("Flipping content isolation flag.");
    // Workaround for
    // https://github.com/puppeteer/puppeteer/blob/ad357986972f6d8e49a1bf8d4b0c0d9e344db189/packages/puppeteer-core/src/node/FirefoxLauncher.ts#L38

    const configPage = await ctx.newPage();
    await configPage.goto('about:config', {
      waitUntil: 'networkidle0'
    });
    await configPage.evaluate(() => {
      Services.prefs.setIntPref('fission.webContentIsolationStrategy', 1)
    });

    await configPage.close();

    const page = await ctx.newPage();

    await page.goto(PAGE_URL, {
      timeout: 2000,
    });

    const pageStr = await page.evaluate(
      () => document.documentElement.innerHTML
    );

    if (!pageStr.includes("Postviewer v5")) {
      const msg =
        "Error: Failed to load challenge page. Please contact admins.";
      log(msg);
      console.error(`Page:${pageStr}`);
      throw new Error(msg);
    }

    log("Adding admin's flag.");
    await page.evaluate((flag) => {
      const blob = new Blob([flag], { type: "text/plain" });

      window.postMessage(
        {
          type: "share",
          files: [
            {
              blob,
              cached: false,
              name: "flag.txt",
            },
          ],
        },
        "*"
      );
    }, FLAG);

    await sleep(1000);

    const bodyHTML = await page.evaluate(
      () => document.documentElement.innerHTML
    );

    if (!bodyHTML.includes("file-") && bodyHTML.includes(".txt")) {
      const msg = "Error: Something went wrong while adding the flag.";
      console.error(`Page:${bodyHTML}`);
      throw new Error(msg);
    }

    log("Successfully added the flag.");
    await page.close();

    log(`Visiting ${url}`);
    const playerPage = await ctx.newPage();

    await playerPage.goto(url, {
      timeout: 2000,
    });

    await sleep(5 * 60 * 1000);
  } catch (err) {
    log("Browser error");
    console.log(err);
  } finally {
    log("Browser closing");
    if (browser) await browser.close();
    browser = null;
  }
};

module.exports = { visit };

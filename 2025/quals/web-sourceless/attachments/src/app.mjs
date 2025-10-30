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

import express from "express";
import puppeteer from "puppeteer";
import { computeExecutablePath } from '@puppeteer/browsers';

const app = express();
const PORT = process.env.PORT || 1338;

const firefoxExecutablePath = computeExecutablePath({
  browser: 'firefox',
  buildId: 'stable_138.0.4',
  cacheDir: process.env.PUPPETEER_CACHE_DIR,
});

async function visit(url) {
  let browser;
  try {
    browser = await puppeteer.launch({
      browser: "firefox",
      headless: true,
      userDataDir: '/tmp/firefox-userdata',
      executablePath: firefoxExecutablePath,
      pipe: true,
    });

    const ctx = await browser.createBrowserContext();
    const page = await ctx.newPage();

    console.log(`Visiting: ${url}`);
    await page.goto(url, { timeout: 2000 });

    await new Promise((r) => setTimeout(r, 10_000));
  } catch (err) {
    console.log(err);
  } finally {
    if (browser) await browser.close();
  }
}

app.get("/", (req, res) => {
  const url = req.query.url;
  res.set("content-type", "text/html;charset=utf8");
  if (url && typeof url === "string") {
    visit(url);
    res.write("<p>Adming will soon visit your page<p>");
  }
  res.end(
    `<form><input name=url placeholder=https://example.org><button>submit>`
  );
});

app.listen(PORT, () => {
  console.log(`App listening on port ${PORT}`);
  console.log("Press Ctrl+C to quit.");
});

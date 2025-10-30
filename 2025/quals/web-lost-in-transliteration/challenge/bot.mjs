#!/usr/bin/node
// Copyright 2025 Google LLC
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

import * as puppeteer from "puppeteer";
import { readFileSync, mkdirSync, rmSync } from "node:fs";

const FLAG = readFileSync("/home/user/flag.txt").toString("utf-8").trim();

const url = process.argv[2];
if (!url) {
  process.stderr.write("url is mandatory\n");
  process.exit(1);
}

const rand = Math.random().toString(16).slice(2);
const userDataDir = `/tmp/chrome-userdata-${rand}`;
const crashesDir = `/tmp/chrome-crashes-${rand}`;

function cleanup() {
  rmSync(userDataDir, {recursive: true, force: true});
  rmSync(crashesDir, {recursive: true, force: true});
}

mkdirSync(userDataDir);
mkdirSync(crashesDir);

const browser = await puppeteer.launch({
  executablePath:
    "/home/user/puppeteer_cache/chrome/linux-136.0.7103.94/chrome-linux64/chrome",
  headless: true,
  args: [
    `--user-data-dir=${userDataDir}`,
    `--breakpad-dump-location=${crashesDir}`,
  ],
});

const proc = browser.process();

const TIMEOUT = 10_000;
const timeoutId = setTimeout(() => {
  try {
    proc.kill();
    cleanup();
  } finally {
    process.exit(124);
  }
}, TIMEOUT);
timeoutId.unref();

try {
  const context = await browser.createBrowserContext();
  const page = await context.newPage();
  await page.evaluateOnNewDocument((flag) => {
    if (window.origin === "http://localhost:1337") {
      localStorage.setItem("flag", flag);
    }
  }, FLAG);
  await page.goto(url, { waitUntil: "networkidle2" });
  const content = await page.content();

  // This is only for debugging purposes.
  process.stdout.write(content);
} finally {
  await browser.close();
  try {cleanup();} finally {}
}

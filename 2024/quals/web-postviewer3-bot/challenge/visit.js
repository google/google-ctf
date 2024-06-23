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
const FLAG = process.env.FLAG || "CTF{dummy_flag}";
const PAGE_URL =
  process.env.PAGE_URL || "https://postviewer3-web.2024.ctfcompetition.com/";
const crypto = require("crypto").webcrypto;

const sleep = (d) => new Promise((r) => setTimeout(r, d));

function randString() {
  const randValues = new Uint32Array(3);
  crypto.getRandomValues(randValues);
  return randValues.reduce((a, b) => a + b.toString(36), "");
}

async function visitUrl(_ctx, url, sendToPlayer) {
  const context = await _ctx;
  const page = await context.newPage();
  await page.goto(PAGE_URL, {
    timeout: 2000,
  });

  const pageStr = await page.evaluate(() => document.documentElement.innerHTML);

  if (!pageStr.includes("Postviewer v3")) {
    const msg = "Error: Failed to load challenge page. Please contact admins.";
    console.error(`Page:${pageStr}`);
    sendToPlayer(msg);
    throw new Error(msg);
  }

  sendToPlayer("Adding admin's flag.");
  await page.evaluate(
    (flag, randName) => {
      const db = new DB();
      db.clear();
      const blob = new Blob([flag], { type: "text/plain" });
      db.addFile(new File([blob], `flag-${randName}.txt`, { type: blob.type }));
    },
    FLAG,
    randString()
  );

  await page.reload();
  await sleep(1000);

  const bodyHTML = await page.evaluate(
    () => document.documentElement.innerHTML
  );

  if (!bodyHTML.includes("file-") && bodyHTML.includes(".txt")) {
    const msg = "Error: Something went wrong while adding the flag.";
    console.error(`Page:${bodyHTML}`);
    throw new Error(msg);
  }

  sendToPlayer("Successfully added the flag.");
  await page.close();

  sendToPlayer(`Visiting ${url}`);
  const playerPage = await context.newPage();
  await playerPage.goto(url, {
    timeout: 2000,
  });
}

module.exports = {
  visitUrl,
  args: {
    headless: false,
    args: ["--enable-features=StrictOriginIsolation"],
  },
};

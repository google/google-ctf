/**
 * Copyright 2024 Google LLC
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
const fs = require("fs");
const path = require("path");
const express = require("express");
const Recaptcha = require("express-recaptcha").RecaptchaV3;
const bot = require("./bot.js");
const pages = require("./pages.json");

const CAPTCHA_SITE_KEY =
  process.env.CAPTCHA_SITE_KEY || "missing";
const CAPTCHA_SECRET_KEY =
  process.env.CAPTCHA_SECRET_KEY || "missing";

const app = express();

const recaptcha = new Recaptcha(CAPTCHA_SITE_KEY, CAPTCHA_SECRET_KEY, {
  hl: "en",
  callback: "captcha_cb",
});

app.use(express.static(path.join(__dirname, "public")));
app.use(express.urlencoded({ extended: true }));

app.get("/", async (req, res) => {
  fs.readFile("index.html", function (err, data) {
    res.writeHead(200, { "Content-Type": "text/html; charset=utf-8" });
    res.write(data);
    return res.end();
  });
});

app.get("/sap.html", async (req, res) => {
  fs.readFile("sap.html", function (err, data) {
    res.writeHead(200, { "Content-Type": "text/html; charset=utf-8" });
    res.write(data);
    return res.end();
  });
});

app.get("/pages.json", (req, res) => {
  res.json(pages);
});

app.get("/sap/:p", async (req, res) => {
  if (!pages.hasOwnProperty(req.params.p)) {
    res.status(404).send("not found");
    return res.end();
  }
  const p = pages[req.params.p];
  res.json(p);
});

app.post("/share", recaptcha.middleware.verify, async (req, res, next) => {
    if (req.recaptcha.error) {
        console.error(req.recaptcha.error);
        res.status(400).send("captcha error");
        return;
    }
    
  const url = req.body.url;
  if (typeof url !== "string") {
    res.status(200).send("invalid url").end();
    return;
  }

  bot.visit(url);
  res.send("Done!").end();
});

const PORT = process.env.PORT || 1337;

app.listen(PORT, () => {
  console.log(`The app is listening on localhost:${PORT}`);
});

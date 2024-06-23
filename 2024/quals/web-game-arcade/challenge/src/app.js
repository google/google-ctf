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

const express = require("express");
const net = require("net");
const Recaptcha = require("express-recaptcha").RecaptchaV3;

const XSSBOT_DOMAIN = process.env.XSSBOT_DOMAIN || "game-arcade-bot";
const XSSBOT_PORT = process.env.XSSBOT_PORT || 1337;
const NO_CAPTCHA = process.env.NO_CAPTCHA || "no-captcha";
const CAPTCHA_SITE_KEY =
  process.env.CAPTCHA_SITE_KEY || "6LePlW8mAAAAACxrLLlBsTPG4mJEP4LB7owGXsUh";
const CAPTCHA_SECRET_KEY =
  process.env.CAPTCHA_SECRET_KEY || "6LePlW8mAAAAALVuekBuUaePCLBHKnYritAm4XSF";
const PORT = process.env.PORT || 1337;

const cache_header = (req, res, next) => {
  res.set("Cache-control", "public, max-age=300");
  res.setHeader("Referrer-Policy", "no-referrer");
  return next();
};
const sec_headers = (req, res, next) => {
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("X-Frame-Options", "DENY");
  res.setHeader("Cross-Origin-Opener-Policy", "same-origin");
  return next();
};

const app = express();
app.set("view engine", "ejs");

app.use("/static/", express.static("static"));

app.use(express.urlencoded({ extended: false }));
app.use(express.json());

const recaptcha = new Recaptcha(CAPTCHA_SITE_KEY, CAPTCHA_SECRET_KEY, {
  hl: "en",
  callback: "captcha_cb",
});

app.get("/", cache_header, (req, res) => {
  res.render("index");
});

app.get(
  "/bot",
  sec_headers,
  cache_header,
  recaptcha.middleware.render,
  (req, res) => {
    res.render("bot", { captcha: res.recaptcha });
  }
);

app.post("/bot", sec_headers, recaptcha.middleware.verify, async (req, res) => {
  res.setHeader("Content-type", "text/plain");

  const url = req.body.url;
  if (typeof url !== "string") {
    return res.send("Invalid type for URL");
  }

  if (req.headers["x-admin-secret"] !== NO_CAPTCHA) {
    if (req.recaptcha.error) {
      console.error(req.recaptcha.error);
      res.send("captcha error");
      return;
    }

    if (url.length > 256) {
      return res.send("Too long URL!");
    }
    if (!/^https?:\/\//.test(url)) {
      return res.send("The URL needs to start with https?://");
    }
  }

  const client = net.Socket();
  client.connect(XSSBOT_PORT, XSSBOT_DOMAIN);
  await new Promise((resolve) => {
    client.on("data", (data) => {
      let msg = data.toString();
      if (msg.includes("Please send me")) {
        client.write(url + "\n");
        console.log(`sending to bot: ${url}`);
      } else {
        res.write(msg + "\n");
        if (/(Timeout|Error): /.test(msg)) {
          res.write("Done.\n");
          res.end();
        }
      }
    });
  });
});

app.get("*", (req, res) => {
  res.set("X-Frame-Options", "DENY");
  res.set("Content-Security-Policy", "default-src 'none'");
  res.send("Not found");
});

app.listen(PORT, () => {
  console.log(`App listening on port ${PORT}`);
  console.log("Press Ctrl+C to quit.");
});

module.exports = app;

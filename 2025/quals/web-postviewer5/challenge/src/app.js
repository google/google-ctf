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

const express = require("express");
const { visit } = require('./bot.js');

const PORT = process.env.PORT || 1338;

const sec_headers = (req, res, next) => {
  res.set("Cache-control", "public, max-age=300");
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("X-Frame-Options", "DENY");
  res.setHeader("Referrer-Policy", "no-referrer");
  return next();
};

const app = express();

app.use(sec_headers);


app.use(express.urlencoded({ extended: false }));

app.set("view engine", "ejs");
app.use("/static/", express.static("static"));

console.log(process.env);

app.get("/", (req, res) => {
  res.render("index");
});

app.get("/bot", (req, res) => {
  res.render("bot");
});

app.post("/bot", async (req, res) => {
  const { url } = req.body;

  res.writeHead(200, {
    'Content-Type': "text/event-stream",
    'Cache-Control': "no-cache",
    'Connection': "keep-alive"
  });

  if (typeof url !== 'string' || !/^https?:\/\//.test(url)) {
    return res.end('nice try');
  }

  function log(msg) {
    res.write(msg + '\n');
  }

  res.write('URL was sent to admin\n');
  try {
    await visit(url, log);
  } catch (e) {
    res.write("error.");
  } finally {
    res.end('done.');
  }
});

app.listen(PORT, () => {
  console.log(`App listening on port ${PORT}`);
  console.log("Press Ctrl+C to quit.");
});

module.exports = app;

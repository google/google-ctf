/**
 * Copyright 2023 Google LLC
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

goog.module("sap");

const Uri = goog.require("goog.Uri");

function getHost(options) {
  if (!options.host) {
    const u = Uri.parse(document.location);

    return u.scheme + "://sappy-web.2024.ctfcompetition.com";
  }
  return validate(options.host);
}

function validate(host) {
  const h = Uri.parse(host);
  if (h.hasQuery()) {
    throw "invalid host";
  }
  if (h.getDomain() !== "sappy-web.2024.ctfcompetition.com") {
    throw "invalid host";
  }
  return host;
}

function buildUrl(options) {
  return getHost(options) + "/sap/" + options.page;
}

exports = { buildUrl };

window.buildUrl = buildUrl;

const API = { host: location.origin };

const output = document.getElementById("output");

window.addEventListener(
  "message",
  async (event) => {
    let data = event.data;
    if (typeof data !== "string") return;
    data = JSON.parse(data);
    const method = data.method;
    switch (method) {
      case "initialize": {
        if (!data.host) return;
        API.host = data.host;
        break;
      }
      case "render": {
        if (typeof data.page !== "string") return;
        const url = buildUrl({
          host: API.host,
          page: data.page,
        });
        const resp = await fetch(url);
        if (resp.status !== 200) {
          console.error("something went wrong");
          return;
        }
        const json = await resp.json();
        if (typeof json.html === "string") {
          output.innerHTML = json.html;
        }
        break;
      }
    }
  },
  false
);

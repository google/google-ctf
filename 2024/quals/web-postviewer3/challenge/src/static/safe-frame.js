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

function arrayToBase36(arr) {
  return arr
    .reduce((a, b) => BigInt(256) * a + BigInt(b), BigInt(0))
    .toString(36);
}

async function calculateHash(...strings) {
  const encoder = new TextEncoder();
  const string = strings.join("");
  const hash = await crypto.subtle.digest("SHA-256", encoder.encode(string));
  return arrayToBase36(new Uint8Array(hash)).padStart(50, "0").slice(0, 50);
}

async function safeFrameRender(body, mimeType, product, shimOrigin, container) {
  const url = new URL(shimOrigin);
  const hash = await calculateHash(body, product, window.origin, location.href);
  url.host = `sbx-${hash}.${url.host}`;
  url.pathname = product + "/shim.html";
  url.searchParams.set("o", window.origin);

  var iframe = document.createElement("iframe");
  iframe.src = url;
  container.appendChild(iframe);
  iframe.addEventListener(
    "load",
    () => {
      iframe.contentWindow?.postMessage(
        { body, mimeType, salt: location.href },
        url.origin
      );
    },
    { once: true }
  );

  return { safeFrame: iframe, safeFrameOrigin: url.origin };
}

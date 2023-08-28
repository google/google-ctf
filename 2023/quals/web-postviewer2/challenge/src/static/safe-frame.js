/**
 * Copyright 2023 Google LLC
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

function generateRandomPart(){
    const randValues = new Uint32Array(3);
    crypto.getRandomValues(randValues);
   return randValues.reduce((a, b) => a + b.toString(36), '');
}

async function previewIframe(body, mimeType, shimUrl, container, sandbox = ['allow-scripts']) {
    const url = new URL(shimUrl);
    url.host = `sbx-${generateRandomPart()}.${url.host}`;
    url.searchParams.set('o', window.origin);

    var iframe = document.createElement('iframe');
    iframe.src = url;
    container.appendChild(iframe);
    iframe.addEventListener('load', () => {
        iframe.contentWindow?.postMessage({ body, mimeType, sandbox}, url.origin);
    }, { once: true });
}
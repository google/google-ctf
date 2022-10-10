/**
 * Copyright 2022 Google LLC
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

const SHIM = `<!DOCTYPE html>
<html lang="en">
<head>
    <meta http-equiv="Content-Type" content="text/html; charset=UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>SHIM</title>
</head>
<body>
    <script>
        onmessage = (e) => {
            if (e.data.body === undefined || !e.data.mimeType) {
                return;
            };
            const blob = new Blob([e.data.body], {
                type: e.data.mimeType
            });
            onunload = () => e.source.postMessage("blob loaded", "*");
            location = URL.createObjectURL(blob);
        };
    <\\/script>
</body>

</html>`

const SHIM_DATA_URL = `data:text/html,<script>
    location=URL.createObjectURL(new Blob([\`${SHIM}\`], {type:"text/html"}))
</script>`;

async function previewIframe(container, body, mimeType) {
    var iframe = document.createElement('iframe');
    iframe.src = SHIM_DATA_URL;
    container.appendChild(iframe);
    iframe.addEventListener('load', () => {
        iframe.contentWindow?.postMessage({ body, mimeType }, '*');
    }, { once: true });
}
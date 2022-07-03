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

const sleep = d => new Promise(r=>setTimeout(r,d));

async function sha1(message) {
    const buffer = new TextEncoder().encode(message);                           
    const hashBuffer = await crypto.subtle.digest('SHA-1', buffer);           
    const hashArray = Array.from(new Uint8Array(hashBuffer));                    
    return hashArray.map(b => b.toString(16).padStart(2,'0')).join(''); 
}

async function appendFileInfo(fileInfo){
    const ul = document.querySelector('#filesList');
    const row = document.createElement('a');
    row.className = "list-group-item list-group-item-action";
    const fileId = await sha1(fileInfo.name);
    row.href = '#file-' + fileId;
    row.id = 'file-' + fileId;
    row.innerText = fileInfo.name;
    row.dataset.name = fileInfo.name;
    ul.appendChild(row);
}
async function previewFile(file){
    const previewIframeDiv = document.querySelector('#previewIframeDiv');
    previewIframeDiv.innerText = '';
    await sleep(100);
    previewIframe(previewIframeDiv, file, file.type || 'application/octet-stream');
}

function scale(val){
    const previewIframeDiv = document.querySelector('#previewIframeDiv');
    const iframe = previewIframeDiv.querySelector('iframe');
    const scaleSpan = document.querySelector('#scaleSpan');
    if(iframe === null) return;
    let scale = Number(iframe.style.transform.match(/scale\(([^)]+)\)/)?.[1]) || 1;
    scale += val;
    if(scale <= 0.2) scale = 0.2;
    iframe.style.transformOrigin = '0 0';
    iframe.style.transform = `scale(${scale})`;
    iframe.style.width = (100 / scale) + '%'
    iframe.style.height = (100 / scale) + '%'
    scaleSpan.innerText = Math.floor(scale * 100) + '%';
}
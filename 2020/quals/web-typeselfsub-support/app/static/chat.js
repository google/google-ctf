/**
 * Copyright 2020 Google LLC
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
// Assign handler to message event
window.addEventListener('message', handleMessage, false);

function handleMessage(ev) {
  if(ev.data.reason) {
    log(ev.data.reason)
    getResponse(ev.data.reason)
  }
  if(ev.data.msg){
    getResponse(ev.data.msg)
    top.postMessage({msg:ev.data.msg},'*')
  }
}

function log(html) {
  document.body.innerHTML += html
}


function getResponse(msg) {
  x = new XMLHttpRequest();
  x.addEventListener("load", gotResponse);
  x.open("POST","/chatting");
  x.setRequestHeader("Content-Type","application/x-www-form-urlencoded")
  x.send(`msg=${encodeURIComponent(msg)}`)
}

function gotResponse(data) {
  resp = JSON.parse(this.response);
  top.postMessage({resp:resp.msg},'*')
}

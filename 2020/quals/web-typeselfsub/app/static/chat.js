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
function initiateChat() {
  csrf = document.getElementById("csrf").value
  reason = document.getElementById("reason").value
  x = new XMLHttpRequest();
  x.addEventListener("load", chatLoad);
  x.onerror = chatFail
  x.open("POST","/initiateChat");
  x.setRequestHeader("Content-Type","application/x-www-form-urlencoded")
  x.send(`csrf=${csrf}&reason=${reason}`);
  startChat()
}

function chatFail() {
  newInfo("Error connecting to chat session");
}

function closeChat() {
  document.getElementById("chatRender").style.visibility = "hidden";
}

function startChat() {
  document.getElementById("chatRender").style.visibility = "visible";
  newInfo("You are being connected please wait...")
}
function chatLoad(){
  resp = JSON.parse(this.response);
  if(resp.error) {
    return chatFail()
  }
  reason = document.getElementById("reason").value
  document.getElementById("chatWindow").contentWindow.postMessage({uuid:resp.uuid,reason:resp.reason},'*')
}

function postChatMsg(msg) {
  document.getElementById("chatWindow").contentWindow.postMessage({msg:msg},'*')
}

function msgbtnclick() {
  msg = document.getElementById("msg").value;
  document.getElementById("msg").value = "";
  postChatMsg(msg);
}
window.addEventListener('message', handleMessage, false);

function handleMessage(ev) {
  if(ev.data.msg) {
    newMsg(ev.data.msg)
  }
  if(ev.data.resp) {
    newResp(ev.data.resp)
  }
  if(ev.data.info) {
    newInfo(ev.data.info)
  }
}

function newInfo(msg) {
  msgDiv = document.createElement("div");
  msgDiv.innerText =  msg;
  msgDiv.className = "infoDiv";
  document.getElementById("chatText").appendChild(msgDiv);
}


function newResp(msg) {
  msgDiv = document.createElement("div");
  msgDiv.innerText =  msg;
  msgDiv.className = "respDiv";
  document.getElementById("chatText").appendChild(msgDiv);
}
function newResp(msg) {
  msgDiv = document.createElement("div");
  msgDiv.innerText =  msg + " <";
  msgDiv.className = "respDiv";
  document.getElementById("chatText").appendChild(msgDiv);
}

function newMsg(msg) {
  msgDiv = document.createElement("div");
  msgDiv.innerText =  "> " + msg;
  msgDiv.className = "msgDiv";
  document.getElementById("chatText").appendChild(msgDiv);
}

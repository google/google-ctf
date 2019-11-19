// Copyright 2019 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

(() => {
  class EscapedHtml {
    constructor(html) {
      this.html = html;
    }

    toString() {
      return this.html;
    }
  };

  const render = (strings, ...values) => {
    let output = strings[0];
    for (let i = 0; i < values.length; i++) {
      let value = values[i];
      if (typeof value == 'string') {
        value = value.replace('<', '&lt;').replace('>', '&gt;');
      } else if (Array.isArray(value)) {
        value = value.join('');
      }
      output += value;
      output += strings[i + 1];
    }
    return new EscapedHtml(output);
  };

  const renderAsNode = (strings, ...values) => {
    const escapedHtml = render(strings, ...values);
    const element = document.createElement('div');
    element.innerHTML = escapedHtml.toString();
    if (element.childNodes.length > 1) {
      return element;
    } else {
      return element.removeChild(element.firstChild);
    }
  };

  const renderSignupAsNode = () => {
    return renderAsNode `<h1>Sign Up For Saber.ninja</h1>
    <span class="welcome">Welcome to <span class="bold">Saber.ninja</span> the most secure* Beat Saber website,
     in this site you can share all your favorite beat saber maps with all your friends (and enemies)!</span><br><br>
    Usernames are assigned, please enter a unique password.<br><br>
    <form action="/signup" method="POST">
      <label for="username">Username</label>
      <input name="username" id="username" type="text" value="fcfs" disabled=true />
      <br />
      <label for="password">Password</label>
      <input name="password" id="password" type="password"/>
      <br />
      <input class="button" type="submit" />
    </form>`;
  };

  const renderUploadsAsNode = (uploads) => {
    const node = renderAsNode `<div class="container">
      <div class="sidebar">
        <h2>My Uploads</h2>
        <ul class="upload-list">${
            uploads.map(m => render `<li><a class="level-link" data-id="${m.id}" href="#">${m.name}</a></li>`)
        }</ul>
        <div class="upload-instruction">
          Upload a BeatSaber level (.bsl) file, <a href="/example.bsl">Example</a>
        </div>
        <form action="/upload" method="POST" encType="multipart/form-data">
          <input name="bundle" id="bundle" type="file"/>
          <br />
          <input class="button" type="submit" value="Upload" />
        </form>
        <div class="chat">
          <div class="title">Chat</div>
          <div class="title dotted-border">Contacts</div>
          <div class="contacts">
            <div class="contact active-contact">sgt-pepper</div>
            <button class="disabled" disabled type="button" title="Your account must be an active contributor for 72 hours first!">+ Contact</button>
          </div>
          <div id="message-content">
            <div class="friend">
              <div class="bubble">Hello!</div>
            </div>
          </div>
          <form class="message-form">
            <textarea id="message-input" name="message"></textarea>
            <input id="send-message-btn" class="button" type="submit"/>
          </form>
        </div>
      </div>
      <div class="content-container">
        <div id="preview-pane" class="preview-pane"></div>
        <iframe id="preview-iframe" src="/stage.html"></iframe>
      </div>
    </div>`;
    node.querySelectorAll(".level-link").forEach((link) => {
      link.addEventListener('click', (evt) => {
        switchToLevel(evt.target.getAttribute('data-id'));
        evt.preventDefault();
      });
    });
    const submitButton = node.querySelector("#send-message-btn");
    submitButton.addEventListener('click', (evt) => {
      sendMessage();
      evt.preventDefault();
    });
    return node;
  }

  const getUploads = () => {
    return JSON.parse(document.getElementById('upload-metadata').textContent);
  };

  const renderPreviewAsNode = ({id, name, song, artist, uploader}) => {
    return renderAsNode `<div class="preview-banner">
      <img src="/level/${id}/cover" class="cover"/>
      <div>
        <p>${name}</p>
        <p>${song} by ${artist}</p>
        <p>Uploaded by ${uploader}</p>
      </div>
    </div>
    <div>
      <a href="/level/${id}/beatmap" download="beatmap.dat">Beatmap</a> -
      <a href="/level/${id}/bundle">Bundle</a><br>
      Share this level: <a href="/preview/${id}">/preview/${id}</a><br>
      <button id="start-button" class="button">Start</button>
      <button id="stop-button" class="button">Stop</button>
    </div>`;

  }

  const switchToLevel = (id) => {
    const previewPane = document.getElementById('preview-pane');
    const level = getUploads().filter(upload => upload.id == id)[0];
    let preview = null;
    for (let child of previewPane.childNodes) {
      child.style.display = 'none';
      if (child.getAttribute('data-id') == id) {
        child.style.display = null;
        preview = child;
      }
    }
    if (!preview) {
      preview = renderPreviewAsNode(level);
      preview.setAttribute('data-id', id);
      preview.setAttribute('id', 'preview-node');

      // Add start and stop buttons
      const startbutton = preview.querySelector('#start-button');
      startbutton.setAttribute('data-id', id);
      startbutton.addEventListener('click', (evt) => {
        switchToLevel(evt.target.getAttribute('data-id'));
        evt.preventDefault();
      });

     preview.querySelector("#stop-button").addEventListener('click', (evt) => {
          stopPlay();
          evt.preventDefault();
      });

      previewPane.appendChild(preview);
    }
    const iframe = document.querySelector('#preview-iframe');
    const iframeBody = iframe.contentWindow.document.body;

    for (let child of iframeBody.childNodes) {
      if (child.classList && child.classList.contains('bs-stage')) {
        iframeBody.removeChild(child);
      }
    }

    window.history.replaceState({}, 'saber.ninja', '/');

    (async () => {
      const bpm = level.beatsPerMinute;
      const json = await (await fetch(`/level/${level.id}/beatmap`)).json();
      const steps = {};
      const stageNode = document.createElement("div");
      stageNode.classList.add("bs-stage");
      window.addEventListener("deviceorientation", e=>{
          stageNode.style.setProperty('--beta', e.beta);
          stageNode.style.setProperty('--gamma', e.gamma);
      }, true);
      json._notes.forEach(note => {
        steps[note._time] = steps[note._time] || (()=>{
            const stepNode = document.createElement('div');
            stepNode.classList.add("bs-step");
            stepNode.style.setProperty('--time', (60*note._time/bpm) + "s");
            stageNode.insertBefore(stepNode, stageNode.firstChild);
            return stepNode;
        })();
        const noteNode = document.createElement('div');
        steps[note._time].appendChild(noteNode);
        noteNode.classList.add(...[
          'bs-square',
          'bs-square-row-' + (3 - note._lineLayer),
          'bs-square-col-' + (note._lineIndex + 1),
          'bs-square-color-' + ['red', 'blue'][note._type],
          'bs-square-angle-' + [
            'bottom', 'top', 'right', 'left',
            'bottom-right', 'bottom-left',
            'top-right', 'top-left',
            'circle'
          ][note._cutDirection]
        ]);
      });
      let audioNode = document.createElement("audio");
      audioNode.setAttribute('class',"audio-node");
      audioNode.preload = "auto";
      audioNode.src = `/level/${id}/song`;
      audioNode.oncanplaythrough = () => {
          audioNode.play();
      };
      audioNode.onplay = () => {
        iframeBody.appendChild(stageNode);
        iframeBody.appendChild(audioNode);
        iframe.style.display = 'block';
      };
    })();
  }

  const page = document.getElementById('page');
  if (document.body.getAttribute('data-needs-signup') === 'true') {
    page.appendChild(renderSignupAsNode());
  } else {
    page.appendChild(renderUploadsAsNode(getUploads()));

    const previewMetadata = document.getElementById('preview-metadata');
    if (previewMetadata) {
      const previewLevel = JSON.parse(previewMetadata.textContent);
      const preview = renderPreviewAsNode(previewLevel);
      const previewPane = document.getElementById('preview-pane');
      previewPane.appendChild(preview);
    }
  }

  const stopPlay = function(){
    const iframe = document.body.querySelector("#preview-iframe");
    const node = iframe.contentWindow.document.body;

    for (let child of node.childNodes) {
      if (child.classList && child.classList.contains('bs-stage')) {
        node.removeChild(child);
      }
    }
    for (let child of node.childNodes) {
      if (child.classList && child.classList.contains('audio-node')) {
        node.removeChild(child);
      }
    }
    iframe.style.display = 'none';
  }

  const newMsgBubble = function(cont, owned) {
    const el = document.createElement('div');
    const bubbleEl = document.createElement('div');
    el.appendChild(bubbleEl);
    bubbleEl.textContent = cont;
    bubbleEl.classList = "bubble";
    if(owned){
      el.classList = "self";
    } else {
      el.classList = "friend";
    }
    return el;
  }

  const sendMessage = function() {
    const messages = document.getElementById('message-content');
    const messageInput = document.getElementById("message-input");
    const messageText = messageInput.value;
    if(!messageText){
      return false;
    }
    const msgEl = newMsgBubble(messageInput.value, true);
    messageInput.value = '';
    messages.appendChild(msgEl);

    fetch(`/chat`, {method:'POST', body: JSON.stringify({message:messageText}),headers: { "Content-Type": "application/json" }})
      .then((resp) => resp.json()).then((json) => {
        const respEl = newMsgBubble(json.message, false);
        messages.appendChild(respEl);
        messages.scrollTo(0,messages.scrollHeight);
    });
    return false;
  }

})();

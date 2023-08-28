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

import {trustedResourceUrl} from 'safevalues';
import {safeScriptEl} from 'safevalues/dom';

if (location.pathname !== '/') {
  const viewPath = location.pathname.split('/view/');
  const uuidRe = new RegExp('^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$');
  if (viewPath.length !== 2 || !uuidRe.test(viewPath[1])) {
    location.href = '/';
  }

  interestObj = {"favorites":{}};
  const uuid = viewPath[1];
  const xhr = new XMLHttpRequest();
  xhr.addEventListener("load", () => {
    if (xhr.status === 200) {
      const json = JSON.parse(xhr.response);
      for (const key of Object.keys(json)) {
        if (interestObj[key] === undefined) {
          interestObj[key] = json[key];
        } else{
          Object.assign(interestObj[key], json[key]);
        }
      }
    } else {
      alert(xhr.response);
      location.href = '/';
    }
  });
  xhr.open('GET', `/bio/${uuid}`, false);
  xhr.send();
}

function setContent(key, value) {
  document.querySelector(`#bio-${key}`).textContent = `${key}: ${value}`;
}

function render() {
  if (location.pathname === '/') {
    const editHtml = document.querySelector('#bio-edit').content;
    document.querySelector('#edit-div').appendChild(editHtml);
    const form = document.querySelector('#form');
    const button = document.querySelector('#save');
    form.addEventListener('submit', async event => {
      event.preventDefault();
      button.disabled = true;
      const formData = new FormData(form);
      const jsonObj = {};
      const favorites = {};
      formData.forEach((value, key) => {
        if (key === 'food') {
          favorites[key] = formData.getAll(key);
        } else if (key === 'sports' || key === 'hobbies') {
          favorites[key] = value;
        } else {
          jsonObj[key] = value;
        }
      });
      jsonObj['favorites'] = favorites;
      const response = await fetch('/create', {
        method:'POST',
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify(jsonObj)
      });
      if (response.status === 200) {
        const json = await response.json();
        location.href = `/view/${json.id}`;
      } else {
        button.disabled = false;
        const error = await response.text();
        alert(error);
        throw(error);
      }
    });
  } else {
    const viewHtml = document.querySelector('#bio-view').content;
    document.querySelector('#view-div').appendChild(viewHtml);

    setContent('name', interestObj['name']);
    const favorites = interestObj['favorites'];
    if (favorites) {
      for (let key of Object.keys(favorites)) {
        if (key === 'food') {
          setContent(key, favorites[key].join(', '));
        } else {
          setContent(key, favorites[key]);
        }
      }
    }
    
    setInnerHTML(document.querySelector('#bio-html'),
        sanitizer.sanitize(interestObj['introduction']));
        
    const reportButton = document.querySelector('#report');
    reportButton.addEventListener("click", function(){
      reportButton.disabled = true;
      fetch('/report', {
        method:'POST',
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({url: location.href})
      }).then(response => {
        reportButton.disabled = false;
        if (response.status === 200) {
          alert('Report sent!');
        } else {
          alert('An error occured, try again later!');
        }
      });
    });
  }
}

function loadEditorResources() {
  const style = document.querySelector('#editor-style').content;
  document.head.appendChild(style);
  const script = document.createElement('script');
  safeScriptEl.setSrc(script, trustedResourceUrl(editor));
  document.body.appendChild(script);
}

window.addEventListener('DOMContentLoaded', () => {
  render();
  if (!location.pathname.startsWith('/view/')) {
    loadEditorResources();
  }
});


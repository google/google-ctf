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

class Viewer {
  constructor(container) {
    this.container = container;
    this.sandbox = document.createElement('iframe');
    this.sandbox.setAttribute('src', '/sandbox');
    this.sandbox.setAttribute('sandbox', 'allow-same-origin');
    this.sandbox.setAttribute('class', 'sandbox');
    this.sandboxLoaded = new Promise((resolve) => {
      this.sandbox.addEventListener('load', resolve);
    });
    this.sandboxLoaded.then(() => initListener(this.sandbox.contentWindow));
    this.container.appendChild(this.sandbox);
    window.addEventListener('message', async (evt) => {
      if (evt.data.type === 'error' && evt.data.lang) {
        await this.init();
        await this.loadPlugin(evt.data.lang);
      }
    });
  }

  async init() {
    const index = Array.from(document.querySelectorAll('iframe.sandbox'))
        .indexOf(this.sandbox);
    this.config = CONFIG.viewer[index];
    this.loadedPlugins = {};
    await this.sandboxLoaded;
    let loaders = [];
    for (let i = 0; i < this.config.dependencies.length; i++) {
      loaders.push(this.loadScript(this.config.dependencies[i]));
    }
    await Promise.all(loaders);
    loaders = [];
    for (let i = 0; i < this.config.preload.length; i++) {
      loaders.push(this.loadPlugin(this.config.preload[i]));
    }
    await Promise.all(loaders);
  }

  async render(lang, text, fixedSize) {
    await this.loadPlugin(lang);
    this.sandbox.contentWindow.postMessage(
        {type: 'render', lang, text, fixedSize}, origin);
  }

  scroll(offsetTop) {
    this.sandbox.contentWindow.postMessage(
        {type: 'scroll', offsetTop}, origin);
  }

  loadPlugin(lang) {
    if (!this.loadedPlugins[lang]) {
      const promise = (async () => {
        const spec = this.config.plugins[lang];
        if (spec.requires) {
          for (let req of spec.requires) {
            await this.loadPlugin(req);
          }
        }
        await this.loadScript(spec);
      })();
      this.loadedPlugins[lang] = promise;
    }
    return this.loadedPlugins[lang];
  }

  async loadScript(spec) {
    const params = {};
    if (spec.integrity) {
      params.integrity = spec.integrity;
    }
    const resp = await fetch(spec.src, params);
    if (!resp.ok) {
      throw new Error(`${spec.src} failed to load`);
    }
    const script = await resp.text();
    initScript(this.sandbox.contentWindow, script);
  }
}

function initScript(sandboxWindow, script) {
  with (sandboxWindow) {
    eval(script);
  }
}

function initListener(sandboxWindow) {
  with (sandboxWindow) {
    let lastOffsetTop;
    addEventListener('message', (evt) => {
      if (evt.origin == origin) {
        const viewport = document.querySelector('#viewport');
        if (evt.data.type === 'render') {
          while (viewport.children[0]) {
            viewport.children[0].remove();
          }
          try {
            if (!evt.data.fixedSize && evt.data.lang == 'markdown') {
              viewport.innerHTML = marked(evt.data.text, {
                sanitize: true,
                sanitizer: () => '',
              });
            } else {
              const code = document.createElement('code');
              code.setAttribute('class', `language-${evt.data.lang}`);
              code.textContent = evt.data.text;
              const pre = document.createElement('pre');
              pre.appendChild(code);
              viewport.appendChild(pre);
              Prism.highlightAllUnder(viewport);
            }
          } catch (e) {
            window.parent.postMessage(
                {type: 'error', lang: evt.data.lang}, origin);
          }
        } else if (evt.data.type === 'scroll') {
          lastOffsetTop = evt.data.offsetTop;
          requestAnimationFrame(() => {
            viewport.style['top'] = `-${lastOffsetTop}px`
          })
        }
      }
    });
  }
}

function populateRecent() {
  const container = document.querySelector('#recent-container');
  const recent = JSON.parse(localStorage.getItem('recent') || '[]');
  for (let i = 0; i < recent.length; i++) {
    const link = document.createElement('a');
    link.textContent = recent[i].name;
    link.setAttribute('href', recent[i].url);
    const item = document.createElement('li');
    item.appendChild(link);
    container.appendChild(item);
  }
  if (recent.length == 0) {
    const item = document.createElement('li');
    item.textContent = 'Nada. Not a one.';
    container.appendChild(item);
  }
  for (let i = 0; i < recent.length; i++) {
    if (recent[i].url == location.href) {
      recent.splice(i, 1);
      i--;
    }
  }
  if (/^\/view/.test(location.pathname)) {
    recent.unshift(
        {name: document.querySelector('title').text, url: location.href});
  }
  while (recent.length > 10) {
    recent.pop();
  }
  localStorage.setItem('recent', JSON.stringify(recent));
}

async function initCreate() {
  const viewer = new Viewer(document.querySelector('#viewer'));
  await viewer.init();
  const editor = document.querySelector('#editor');
  const langSelect = document.querySelector('#lang');
  const render =
      () => viewer.render(langSelect.value, editor.value + '\n', true);
  langSelect.addEventListener('change', render);
  editor.addEventListener('keydown', (evt) => {
    const keyCode = evt.keyCode || evt.which;
    if (keyCode == 9) {
      evt.preventDefault();
      const start = editor.selectionStart;
      const end = editor.selectionEnd;
      editor.value = editor.value.substring(0, start) +
          '    ' + editor.value.substring(end);
      editor.selectionStart = editor.selectionEnd = start + 4;
      render();
    }
  });
  editor.addEventListener('scroll', () => {
    viewer.scroll(editor.scrollTop);
  })
  editor.addEventListener('input', render);
  render();
  populateRecent();
}

async function initView() {
  const contentEl = document.querySelector('#content');
  const contentLines = contentEl.textContent.split('\n').length;
  const lang = contentEl.getAttribute('data-lang');
  const container = document.querySelector('#viewer');
  if (lang === 'markdown') {
    container.style.height = '400px';
  } else {
    container.style.height = `${24 * contentLines + 24}px`;
  }
  const viewer = new Viewer(container);
  window.doReport = (token) => {
    document.querySelector('#report-form').submit();
  }
  grecaptcha.ready(() => {
    grecaptcha.render(document.querySelector('#report-button'));
  });
  await viewer.init();
  viewer.render(
      contentEl.getAttribute('data-lang'), contentEl.textContent, false);
  populateRecent();
}

if (/^\/create/.test(location.pathname)) {
  initCreate();
} else if (/^\/view/.test(location.pathname)) {
  initView();
}

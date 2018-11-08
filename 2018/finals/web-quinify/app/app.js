#!/usr/bin/env -u <!-- node

// --><title>Quinify</title><body style="white-space: pre-wrap"><script>

//Copyright 2018 Google LLC
//
//Licensed under the Apache License, Version 2.0 (the "License");
//you may not use this file except in compliance with the License.
//You may obtain a copy of the License at
//
//    https://www.apache.org/licenses/LICENSE-2.0
//
//Unless required by applicable law or agreed to in writing, software
//distributed under the License is distributed on an "AS IS" BASIS,
//WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//See the License for the specific language governing permissions and
//limitations under the License.

// You are in a maze of twisty little nested variable contexts, all alike.
// Might you inject some sanity and in so doing, learn the flag.txt?

'use strict';

var k = 0;

// vars_go_here
// /vars_go_here

var bannedTags = { script: 1 };

/**
 * Computes the content of this page but with vars replaced and
 * iterated to convergence.
 *
 * @param {URL} url the URL requested
 * @return {string} similar to this very file, dear reader.
 */
function quineify(url) {
  // If url has ?a=b&c=d, then the declaration comments above surround
  //   var a="b", c="d";
  let replacement =
      Array.from(url.searchParams.entries())
      .filter(([ key ]) => /^[a-z]+$/.test(key))
      .map(([ key, value ]) => ` ${ key }=${ JSON.stringify(filterHtml(value)) }`)
      .join(',')
      || ' vars_go_here';
  const content = getContent().replace(
      /^(\/\/ vars_go_here)$[\s\S]*^(\/\/ \/vars_go_here)$/m,
      (_, start, end) => `${ start }\nvar${ replacement };\n${ end }`);
  // What if our substitution warrants substitution?
  return quineverge(url, content);

  function filterHtml(str) {
    let html = `${ str }`;
    for (;;) {
      let filtered = html.replace(
          /(<[/]?)([a-zA-Z]*)([^">]*>?)/g,
          ( _, prefix, tagName, tagBody ) =>
            (tagName.toLowerCase() in bannedTags)
            ? ' '
            : `${ prefix }${ tagName }>`);
      if (filtered === html) {
        return html;
      }
      html = filtered;
    }
  }
}

/**
 * True if converged or just stop if taking too long.
 * Twisty little passages are no excuse for meandering.
 */
function hasConverged(k, oldContent, newContent) {
  if (!(+k < 5)) {
    return true;
  }
  // k is volatile
  newContent = `${ newContent || '' }`.replace(/ k="\d+"/g, ' k=""');
  oldContent = `${ oldContent || '' }`.replace(/ k="\d+"/g, ' k=""');
  return newContent === oldContent;
}

/**
 * Extracts scripts from the quine content and reruns them at k+1
 * so that we can converge on the same content on the server as
 * we do on the client.
 *
 * @param url the URL requested
 * @param content the content for step k.
 */
function quineverge(url, content) {
  if (hasConverged(k, typeof old_content !== 'undefined' ? old_content : null, content)) {
    return content;
  }

  // You can run server-side JS on the client.  Why not vice-versa?
  const re = /<script>([\s\S]*?)<\/script>/gi;
  const scripts = [];
  for (let match; (match = re.exec(content));) {
    scripts.push(match[1]);
  }

  var document = {
    body: {
      textContent: '',
      parentElement: {
        outerHTML: content,
      },
    },
  };

  var location = new URL(url);

  {
    // Store old content so we can test convergence above.
    let old_content = content;

    for (const script of scripts) {
      try {
        eval(`(() => {\n${ script }\n})()`);
      } catch (ex) {
        /* browsers don't care */
      }
    }
  }

  return document.body.textContent;
}

function getContent() {
  if (typeof document === 'undefined') {
    // If we're server, look on the file-system.
    return require('fs').readFileSync(__filename, { encoding: 'utf8' });
  } else {
    // If we're on the client, look at the document.
    return document.body.parentElement.outerHTML;
  }
}

// Kick off a server or update the current document
// depending on the context in which the code runs.
if (typeof document === 'undefined') {
  global.URL = require('url').URL;
  const express = require('express');

  const PORT = process.env.PORT || 8080;
  const HOSTNAME = process.env.HOSTNAME || 'localhost';
  const BASE_URL = `http://${ HOSTNAME }:${ PORT }/`;

  const app = express();
  app.get('/', (req, res) => {
    const reqUrl = new URL(req.url, BASE_URL);
    reqUrl.hostName = HOSTNAME;
    reqUrl.port = PORT;

    withHumanLanguage(
      reqUrl.searchParams.get('hl') || 'en',
      () => {
        res.status(200);
        res.header('X-XSS-Protection', '0');
        res.header('Content-type', 'text/html; charset=utf8');
        let content = null;
        try {
          content = quineify(reqUrl);
        } catch (exc) {
          res.status(500);
          res.header('Content-type', 'text/plain; charset=utf8');
          content = `${ exc }`;
        } finally {
          res.end(content || '');
        }
      });
  });

  app.listen(PORT, '0.0.0.0', () => {
    console.log(`App listening at http://${ HOSTNAME }:${ PORT }/`);
    console.log('Press Ctrl+C to quit.');
  });
} else {
  const url = new URL(location.href);
  url.searchParams.set('k', k + 1);
  document.body.textContent = quineify(url);
}

/** Respect user's locale server-side. */
function withHumanLanguage(hl, action) {
  // TODO: s/twisty little maze/pequeño laberinto sinuoso/ for example.
  const unbinds = [
    rebind(Date.prototype, 'toString', function toString() { return this.toLocaleString(hl); }),
    rebind(Number.prototype, 'toString', function toString() { return this.toLocaleString(hl); }),
    rebind(String.prototype, 'toLowerCase', function toLowerCase() { return this.toLocaleLowerCase(hl); }),
    rebind(String.prototype, 'toUpperCase', function toUpperCase() { return this.toLocaleUpperCase(hl); }),
  ];
  try {
    action();
  } finally {
    unbinds.forEach((f) => f());
  }

  function rebind(obj, key, value) {
    const orig = Object.getOwnPropertyDescriptor(obj, key);
    delete obj[key];
    Object.defineProperty(obj, key, { value, configurable: true });
    return () => {
      delete obj[key];
      Object.defineProperty(obj, key, orig);
    };
  }
}
// </script>

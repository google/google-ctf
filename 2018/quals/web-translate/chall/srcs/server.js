/*
Copyright 2018 Google LLC

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    https://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/


const express = require('express');
const cookieParser = require('cookie-parser')
const uuidv4 = require('uuid/v4');

// note: To let Domino run in there,
//   sed -i "61s/\'use strict\'//" node_modules/vm2/lib/sandbox.js

const {NodeVM} = require('vm2');
const restrictedFs = require('./restricted_fs.js');

const Memcache = require('memcached-promisify');

////////////////////////////////
// Memcache functions
////////////////////////////////

const memcache = new Memcache({'cacheHost': '127.0.0.1:11211'});

function read_dictionary(id, lang) {
  let key = `${id}_${lang}`;
  return memcache.get(key).then((result) => {
      if (!result)
          return JSON.parse(restrictedFs.load(`i18n/${lang}.json`));
      return result;
  }).catch(console.error);
}

function write_dictionary(id, lang, data) {
  let key = `${id}_${lang}`;
  return memcache.set(key, data, 1*60*60 /*1 hour*/).then(() => {
    return `${id}_${lang}`;
  }).catch(console.error);
}

function delete_dictionary(id, lang) {
  let key = `${id}_${lang}`;
  return memcache.del(key).catch(console.error);
}


////////////////////////////////
// Renderer utilities
////////////////////////////////

function renderHtml(html) {
  var response = '';
  response += restrictedFs.load('static/header.html');
  response += html;
  response += restrictedFs.load('static/footer.html');
  return response;
}

function renderStatic(relativePath) {
  var response = '';
  response += restrictedFs.load('static/header.html');
  response += restrictedFs.load(relativePath);
  response += restrictedFs.load('static/footer.html');
  return response;
}

function renderError(error) {
  console.log(error);
  return renderHtml(`
  Something broke: ${error}<hr/>
  <a href="/reset">reset the challenge</a> or <a href="/">go back</a>`);
}

function renderWithAngular(givenScope, lang, fs, ip) {
  try {
    // Remember the AngularJS sandbox? Only 2010's kids remember.
    const sandbox = new NodeVM ({
      require: {
        external: true,
        builtin: false,
        root: "./",
        import: [
          `./srcs/sandboxed/angularjs_for_domino.js`,
          `./srcs/sandboxed/app.js`,
          `domino`
        ],
        context: 'sandbox',
      },
      sandbox: {},
    });

    let ds = async (lang) => await read_dictionary(ip, lang);

    let renderAngularApp = sandbox.run(`
      const domino = require('domino');
      const initAngularJS = require('./srcs/sandboxed/angularjs_for_domino.js');
      const angularApp = require('./srcs/sandboxed/app.js');
      const I18n = require('./srcs/sandboxed/i18n.js');

      module.exports = async (givenScope, lang, fs, ds) => {
          const i18n = I18n.build(fs, ds);
          const window = domino.createWindow(
              await i18n.forTemplateWithLang(lang, './templates/template.html'),
              'nowhere://¯\\_(ツ)_/¯');
          initAngularJS(window);
          try {
            await angularApp(window, givenScope, i18n, lang);
            return window.document.innerHTML;
          } catch (error) {
            return '<html><head></head><body style="width:600px; margin:auto; margin-top:100px;">' +
                'You broke my AngularJS :( ' + error + '<hr/>' +
                '<a href="/reset">reset the challenge</a> or <a href="/">go back</a>' +
                '</body></html>';
          }
      }
    `, 'server.js');

    return renderAngularApp(givenScope, lang, restrictedFs, ds);
  } catch (e) {
    return renderError(e);
  }
}


////////////////////////////////
// Server setup
////////////////////////////////

const app = express();
const LANG = 'en';

app.set('trust proxy', true);

app.use(cookieParser());


app.use(function (req, res, next) {
  if (req.cookies.sid && req.cookies.sid.toString().match(/^[0-9a-f-]+$/)) {
    req.uid = req.cookies.sid+'';
  } else {
    let uid = uuidv4();
    req.uid = uid;
    res.cookie('sid', uid);
  }
  next();
});

////////////////////////////////
// Routing
////////////////////////////////

app.get('/', async (req, res) => {
  const lang = req.query['lang'] ? req.query['lang'] : LANG;
  const userQuery = req.query['query'] ? req.query['query'] : null;
  res.send(await renderWithAngular({userQuery:userQuery}, lang, restrictedFs, req.uid));
});

// Append to the dictionnaries
app.get('/add', (req, res) => {
  const [word, translated, lang] =
      [req.query['word'],  req.query['translated'], req.query['lang']];

  if (word && translated && lang) {
      let defaultTranslations = JSON.parse(restrictedFs.load(`i18n/${lang}.json`));
      read_dictionary(req.uid, lang).then((translations) => {
      if (!translations)
        translations = defaultTranslations;
        translations[word] = translated;
        return write_dictionary(req.uid, lang, translations);
      }).then(() => {
        res.send(renderHtml(
          `wrote down that ${word} translates to ${translated} in ${lang}.
          <a href="/">go back</a>`));
      }).catch((e) => {
        res.send(renderError(e));
      });
  } else {
    res.send(renderStatic('/static/add.html'));
  }
});

// Display the dictionnaries
app.get('/dump', async (req, res) => {
  let en = await read_dictionary(req.uid, 'en');
  let fr = await read_dictionary(req.uid, 'fr');

  res.send(renderHtml(`
    english dictionary: ${JSON.stringify(en)} <hr/>
    french dictionary:  ${JSON.stringify(fr)} <hr/>
    <a href="/">go back</a>
  `));
});

// A simple endpoint that resets all.
app.get('/reset', (req, res) => {
  delete_dictionary(req.uid, 'en');
  delete_dictionary(req.uid, 'fr');
  res.send(renderStatic('static/reset_done.html'));
});

app.listen(1337, () => console.log('listening on port 1337'));

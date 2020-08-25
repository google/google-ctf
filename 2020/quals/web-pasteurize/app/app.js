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

const express = require('express');
const bodyParser = require('body-parser');
const utils = require('./utils');
const Recaptcha = require('express-recaptcha').RecaptchaV3;
const uuidv4 = require('uuid').v4;
const Datastore = require('@google-cloud/datastore').Datastore;

/* Just reCAPTCHA stuff. */
const CAPTCHA_SITE_KEY = process.env.CAPTCHA_SITE_KEY || 'site-key';
const CAPTCHA_SECRET_KEY = process.env.CAPTCHA_SECRET_KEY || 'secret-key';
console.log("Captcha(%s, %s)", CAPTCHA_SECRET_KEY, CAPTCHA_SITE_KEY);
const recaptcha = new Recaptcha(CAPTCHA_SITE_KEY, CAPTCHA_SECRET_KEY, {
  'hl': 'en',
  callback: 'captcha_cb'
});

/* Choo Choo! */
const app = express();
app.set('view engine', 'ejs');
app.set('strict routing', true);
app.use(utils.domains_mw);
app.use('/static', express.static('static', {
  etag: true,
  maxAge: 300 * 1000,
}));

/* They say reCAPTCHA needs those. But does it? */
app.use(bodyParser.urlencoded({
  extended: true
}));

/* Just a datastore. I would be surprised if it's fragile. */
class Database {
  constructor() {
    this._db = new Datastore({
      namespace: 'littlethings'
    });
  }
  add_note(note_id, content) {
    const note = {
      note_id: note_id,
      owner: 'guest',
      content: content,
      public: 1,
      created: Date.now()
    }
    return this._db.save({
      key: this._db.key(['Note', note_id]),
      data: note,
      excludeFromIndexes: ['content']
    });
  }
  async get_note(note_id) {
    const key = this._db.key(['Note', note_id]);
    let note;
    try {
      note = await this._db.get(key);
    } catch (e) {
      console.error(e);
      return null;
    }
    if (!note || note.length < 1) {
      return null;
    }
    note = note[0];
    if (note === undefined || note.public !== 1) {
      return null;
    }
    return note;
  }
}

const DB = new Database();

/* Who wants a slice? */
const escape_string = unsafe => JSON.stringify(unsafe).slice(1, -1)
  .replace(/</g, '\\x3C').replace(/>/g, '\\x3E');

/* o/ */
app.get('/', (req, res) => {
  res.render('index');
});

/* \o/ [x] */
app.post('/', async (req, res) => {
  const note = req.body.content;
  if (!note) {
    return res.status(500).send("Nothing to add");
  }
  if (note.length > 2000) {
    res.status(500);
    return res.send("The note is too big");
  }

  const note_id = uuidv4();
  try {
    const result = await DB.add_note(note_id, note);
    if (!result) {
      res.status(500);
      console.error(result);
      return res.send("Something went wrong...");
    }
  } catch (err) {
    res.status(500);
    console.error(err);
    return res.send("Something went wrong...");
  }
  await utils.sleep(500);
  return res.redirect(`/${note_id}`);
});

/* Make sure to properly escape the note! */
app.get('/:id([a-f0-9\-]{36})', recaptcha.middleware.render, utils.cache_mw, async (req, res) => {
  const note_id = req.params.id;
  const note = await DB.get_note(note_id);

  if (note == null) {
    return res.status(404).send("Paste not found or access has been denied.");
  }

  const unsafe_content = note.content;
  const safe_content = escape_string(unsafe_content);

  res.render('note_public', {
    content: safe_content,
    id: note_id,
    captcha: res.recaptcha
  });
});

/* Share your pastes with TJMike🎤 */
app.post('/report/:id([a-f0-9\-]{36})', recaptcha.middleware.verify, (req, res) => {
  const id = req.params.id;

  /* No robots please! */
  if (req.recaptcha.error) {
    console.error(req.recaptcha.error);
    return res.redirect(`/${id}?msg=Something+wrong+with+Captcha+:(`);
  }

  /* Make TJMike visit the paste */
  utils.visit(id, req);

  res.redirect(`/${id}?msg=TJMike🎤+will+appreciate+your+paste+shortly.`);
});

/* This is my source I was telling you about! */
app.get('/source', (req, res) => {
  res.set("Content-type", "text/plain; charset=utf-8");
  res.sendFile(__filename);
});

/* Let it begin! */
const PORT = process.env.PORT || 8080;

app.listen(PORT, () => {
  console.log(`App listening on port ${PORT}`);
  console.log('Press Ctrl+C to quit.');
});

module.exports = app;
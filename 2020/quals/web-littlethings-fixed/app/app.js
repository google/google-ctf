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
const cookieSession = require('cookie-session');
const cookieParser = require('cookie-parser');
const bodyParser = require('body-parser');
const crypto = require('crypto');

const {Datastore} = require('@google-cloud/datastore');

const {
  v4: uuidv4
} = require('uuid');


const app = express();
const random = n => crypto.randomBytes(n).toString('hex');
const SECRET_KEY = process.env.NODE_SECRET_KEY || "secret_key";
const COOKIE_SECRET = process.env.COOKIE_SECRET || "terjanq1337";
const FLAG = process.env.FLAG || "flag{secret_flag}";

console.log("SECRET_KEY %s", SECRET_KEY);
console.log("Flag: %s", FLAG);
console.log("COOKIE_SECRET: %s", COOKIE_SECRET);

const DOMAINS = {
  'publicthings-vwatzbndzbawnsfs.web.ctfcompetition.com': {
    public: 'https://publicthings-vwatzbndzbawnsfs.web.ctfcompetition.com',
    private: 'https://fixedthings-vwatzbndzbawnsfs.web.ctfcompetition.com'
  },
  'fixedthings-vwatzbndzbawnsfs.web.ctfcompetition.com':{
    public: 'https://publicthings-vwatzbndzbawnsfs.web.ctfcompetition.com',
    private: 'https://fixedthings-vwatzbndzbawnsfs.web.ctfcompetition.com'
  },
}

const empty_func = () => {};

const theme_gen = (choice) => {
  let theme;
  if (choice !== 2) {
    theme = {
      cb: 'set_light_theme',
      options: {},
      choice: 1,
    }
  } else {
    theme = {
      cb: 'set_dark_theme',
      options: {},
      choice: 2,
    }
  }
  return theme;
};

app.set('view engine', 'ejs');

/* strict routing to prevent /note/ paths etc. */
app.set('strict routing', true);

/* Get hostname */
app.use((req,res,next)=>{
  const host = req.hostname;
  if(!DOMAINS.hasOwnProperty(host)){
    return res.status(500).send("Something wrong with host!");
  }
  req.domains = DOMAINS[host];
  next();
})

class Database {
  constructor() {
    this._db = new Datastore({namespace: 'fixedthings'});
  }

  add_note(note_id, owner_id, content, pub=0, admin=0) {
    if(owner_id == 'admin' && !admin){
      return 'nope';
    }
    const note = {
      note_id: note_id,
      owner: owner_id,
      content: content,
      public: pub,
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
    try{
      note = await this._db.get(key);
    } catch(e) {
      console.error(e);
      return null;
    }
       
    if(!note || note.length < 1){
      return null;
    }
    note = note[0];

    if (note === undefined) {
      return null;
    }

    return note;
  }

  async get_notes(owner_id) {
    let notes = []
    try{
      const q = this._db.createQuery('Note')
        .filter('owner', '=', owner_id);
      [notes] = await this._db.runQuery(q);
      notes.sort((x,y) => x.created - y.created);
      notes = notes.map(x=>({'note_id':x.note_id,'public':x.public}));
    }catch (e){
      console.error(e);
      return [];
    }
  return notes;
  }
}

const DB = new Database();

/* escape string inside string literals */
const escape_string = unsafe => JSON.stringify(unsafe).slice(1, -1)
  .replace(/</g, '\\x3C').replace(/>/g, '\\x3E');

app.use(cookieParser());

/* secure session in cookie */
app.use(cookieSession({
  name: 'session',
  keys: [SECRET_KEY],
  sameSite: 'lax',
}));

/* not extended paramaters, only basic */
app.use(bodyParser.urlencoded({
  extended: false
}))

/* don't allow prototype pollution via req parameters */
app.use((req,res,next)=>{
  for(let key in req.body){
    try{
      req.body[key] = req.body[key].toString();
    }catch{
      return res.status(500).send("Nice try, but no cookie!");
    }
  }

  for(let key in req.query){
    try{
      req.query[key] = req.query[key].toString();
    }catch{
      return res.status(500).send("Nice try, but no cookie!");
    }
  }

  next();
});

/* server static files from static folder */
app.use('/static', express.static('static', {
  etag: true,
  maxAge: 300*1000,
  // maxAge: 0,
}));

const user_mw = async (req, res, next) => {
  if(req.session.user){
    res.locals.user = req.session.user; 
  }else{
    res.locals.user = false;
  }
  next();
}

const try_admin = async (req, res, next) =>{
  if(req.cookies[COOKIE_SECRET] === "1"){
    try{
      console.log('Admin logged in with %s' % COOKIE_SECRET);
      let notes = await DB.get_notes('admin');
      if(notes.length == 0){
        const note_id = uuidv4();
        const admin_note = `
        <h1>Congratulations! You came to the end of the world...</h1>
        <p>As for a reward, here comes your juicy flag <strong>${FLAG}</strong></p>
        `;
        await DB.add_note(note_id, 'admin', admin_note, 0, 1);
        notes = [note_id];
      }
      req.session.user = {
        'username': 'admin',
        'img': "https://media0.giphy.com/media/kdc0nMb8JJZcBsWDgy/giphy.gif",
        'theme': theme_gen(1),
        'id': 'admin',
        'notes': notes,
      }
      req.session.logged = true;
      res.cookie(COOKIE_SECRET, 0, {httpOnly: true});
    }catch(e){
      console.error(e);
    }
  }
   
  next();
};

/* auth middleware */
const auth = async (req, res, next) => {
  if (!req.session.logged || !req.session.user) {
    return res.redirect(`/login?redir=${req.originalUrl}`);
  }
  next();
}

/* disable cache on specifc endpoints */
const nocache = (req, res, next) => {
  res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate');
  res.setHeader('Pragma', 'no-cache');
  res.setHeader('Expires', '0');
  next();
}

/* enable caching on specific endpoints */
const cache = (req, res, next) => {
  res.setHeader('Cache-Control', 'max-age=300');
  next();
}

/* security protection */
const security = (req, res, next) => {
  const nonce = random(8);
  const csp = [
    "default-src 'none'",
    `script-src 'self' 'nonce-${nonce}'`,
    "img-src https: http:",
    "connect-src 'self'",
    "style-src 'self'",
    "base-uri 'none'",
    "form-action 'self'",
    "font-src https://fonts.googleapis.com"
  ]
  res.locals.nonce = nonce;
  res.setHeader('Content-Security-Policy', csp.join(';'));
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('X-Content-Options', 'no-sniff');
  res.setHeader('X-XSS-Auditor', '0');
  // COOP breaks window.name
  // res.setHeader('Cross-Origin-Opener-Policy', 'same-origin');
  next()
}

/* csrf middleware, csrf_token stored in the session cookie */
const csrf_mw = (req, res, next) => {
  const csrf = uuidv4();
  req.csrf = req.session.csrf || uuidv4();
  req.session.csrf = csrf;
  res.locals.csrf = csrf;

  nocache(null, res, empty_func);

  if (req.method !== "POST") {
    return next();
  }

  

  if (req.csrf !== req.body.csrf) {
    res.status(500);
    console.error(req.csrf, req.body.csrf)
    return res.send("Invalid CSRF token");
  }

  next();
}

/* chech if __debug__ is in a URL */
const is_debug = (req, res, next) => {
  res.locals.is_debug = req.query.__debug__ !== undefined ? true : false;
  next();
}

/* jsonp endpoint */
const jsonp = (req, res, next) => {
  res.jsonp = function (obj = {}) {
    const blacklist = /[^\w\.=]/ugi;
    let cb = req.query.cb || 'console.log';
    this.set('Content-type', 'text/javascript; charset=utf-8');

    if (Array.isArray(cb)) {
      cb = cb[0]
    }
    cb = cb.replace(blacklist, '');
    body = `${cb}(${JSON.stringify(obj)})`
    return this.send(body)
  }
  next();
}

const redirect = (req, res) => {
  if (req.session.logged && req.session.user) {
    if(req.query.redir){
      if(/^\/[\w]/.test(req.query.redir)){
        res.redirect(req.query.redir);
        return true;
      }
      try{
        const url = new URL(req.query.redir);
        if(DOMAINS.hasOwnProperty(url.hostname)){
          res.redirect(url.href);
          return true;
        }
      }catch(e){}
    }
    res.redirect('/');
    return true;
  }
  return false;
}

app.use(jsonp);
app.use(is_debug);
app.use(security);

app.get('/', user_mw, (req, res) => {
  res.render('index');
});

app.get('/logout', (req, res) => {
  req.session = null;
  res.redirect('/');
})

// /* the challenge will be open sourced */
// app.get('/source', (req, res) => {
//   res.set("Content-type", "text/plain; charset=utf-8");
//   res.sendFile(__filename);
// })


app.get('/login', try_admin, csrf_mw, user_mw, (req, res) => {
  if(redirect(req,res)) return;
  res.render('login');
});

app.post('/login', csrf_mw, (req, res) => {
  const choice = req.body['script-choice'];
  const theme = theme_gen(parseInt(choice));

  req.session.user = {
    'username': req.body.username || "hacker",
    'img': req.body.img || "/static/images/anonymous.png",
    'theme': theme,
    'id': uuidv4(),
  }
  req.session.logged = true;
  redirect(req,res);
});

app.get('/settings', csrf_mw, auth, user_mw, (req, res) => {
  res.render('settings');
});

app.post('/settings', csrf_mw, auth, (req, res) => {
  const choice = req.body['script-choice'];
  const username = req.body.username;
  const img = req.body.img;

  if (choice) {
    req.session.user.theme = theme_gen(parseInt(choice));
  }
  if (username) {
    req.session.user.username = username;
  }
  if (img) {
    req.session.user.img = img;
  }

  res.redirect('/settings');
});

/* returns basic infor about user to create JS object */
app.get('/me', (req, res) => {
  if (!req.session.user) {
    return res.json({
      username: "guest",
      img: "/static/images/anonymous.png",
      theme: {
        cb: 'set_light_theme',
        options: {},
      },
    });
  }
  return res.json({
    username: req.session.user.username,
    img: req.session.user.img,
    theme: req.session.user.theme
  });
});

app.get('/note', csrf_mw, auth, user_mw, async (req, res) => {
  const notes = await DB.get_notes(req.session.user.id);
  res.render('note_index', {notes});
});

app.post('/note', csrf_mw, auth, async (req, res) => {
  const note = req.body.content;

  if(!note){
    return res.status(500).send("Nothing to add");
  }
  
  if (note.length > 2000) {
    res.status(500);
    return res.send("The note is too big");
  }

  const note_id = uuidv4();
  const owner = req.session.user.id
  const public = req.body.visibility == "public" ? 1 : 0
  try{
    const result = await DB.add_note(note_id, owner, note, public);
    if(!result){
      res.status(500);
      console.error(result);
      return res.send("Something went wrong...");
    }
  }catch(err){
    res.status(500);
    console.error(err);
    return res.send("Something went wrong...");
  }

  return res.redirect('/note');
})

app.get('/note/:id([a-f0-9\-]{36})', auth, user_mw, async (req, res) => {
  const note_id = req.params.id;
  const user_id = req.session.user.id;
  const note = await DB.get_note(note_id);

  if (note.public === 1){
    return res.redirect(`${req.domains.public}/${note_id}`);
  }

  if (note == null || note.owner !== user_id) {
    return res.sendStatus(404);
  }

  const unsafe_content = note.content;
  const safe_content = escape_string(unsafe_content)

  res.render('note', {
    content: safe_content,
    id: note_id,
  });
});

app.get('/theme', cache, (req, res) => {
  res.jsonp({
    version: "b1.13.7",
    timestamp: Date.now()
  });
});

const PORT = process.env.PORT || 80;

app.listen(PORT, () => {
  console.log(`App listening on port ${PORT}`);
  console.log('Press Ctrl+C to quit.');
});

module.exports = app;

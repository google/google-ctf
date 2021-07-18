/**
 * Copyright 2021 Google LLC
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

const express = require("express");
const connect = require("connect");
const session = require('express-session')
const db = require('./db');
const multer = require('multer');
const vhost = require('vhost');
const mime = require('mime');
const highwayhash = require('highwayhash');
const cookieParser = require('cookie-parser');
const MySQLStore = require('express-mysql-session')(session);
const app = express();
const filecomp = express();
const crypto = require('crypto');
const csrf = require('csurf');
const https = require('https');
const fs = require('fs');
const net = require('net');

const server = connect();

const UPLOAD_PATH = process.env.UPLOAD_PATH || './uploads';
const APP_SECRET = process.env.APP_SECRET || crypto.randomBytes(12).toString('base64');
const APP_DOMAIN = process.env.APP_DOMAIN || 'chall.secdriven.localhost';
const APP_2DOMAIN = process.env.APP_2DOMAIN || 'secdrivencontent.localhost';

const DB_HOST = process.env.DB_HOST || "127.0.0.1";
const DB_DATABASE = process.env.DB_DATABASE || "secdriven";
const DB_USER = process.env.DB_USER || "secdriven";
const DB_PASSWORD = process.env.DB_PASSWORD || 'Eesh6asoo8ei';
const DB_PORT = process.env.DB_PORT || "13306";

const MODULO_DOC = 17;
const MODULO_USER = 100000;

const RANDOM_BYTES = process.env.RANDOM_BYTES || Buffer.from("QLrFji6fUUA4jjKN63K0ny4eeWePm4nu")

const ADMIN_FILE_ID = process.env.FILE_ID || 133711377731;

const APP_MAX_FILE_SIZE = parseInt(process.env.APP_MAX_FILE_SIZE) || 500; // in kb

const APP_COOKIE_EXPIRE = 60*1000*60; // 60 minutes;
const FILECOMP_COOKIE_EXPIRE = 5*60*1000; // 5 minutes

const XSSBOT_DOMAIN = process.env.XSSBOT_DOMAIN || 'secdriven-bot';
const XSSBOT_PORT = process.env.XSSBOT_PORT || 1337;

const APP_SHARE_LIMIT = 100;

const LISTEN_PORT = process.env.LISTEN_PORT || 10001;

server.use(vhost(APP_DOMAIN, app));
server.use(vhost('doc-*.'+APP_2DOMAIN, filecomp));

app.use((req, res, next) => {
  res.set('X-Frame-Options', 'DENY');
  res.set('X-Content-Type-Options', 'nosniff');
  res.set('Cache-Control', 'no-cache');
  res.set('Cross-Origin-Opener-Policy', 'same-origin');
  res.set('Referrer-Policy', 'no-referrer');
  const nonce = crypto.randomBytes(4).toString('base64');
  res.locals.csp = {nonce};
  res.set('Content-Security-Policy', `script-src 'self' 'nonce-${nonce}';base-uri 'none'`)
  next();
})

filecomp.use((req, res, next) => {
  res.set('X-Content-Type-Options', 'nosniff');
  res.set('Cache-Control', 'no-cache');
  res.set('Referrer-Policy', 'no-referrer');
  next();
})

app.use(express.urlencoded({extended:false}));
app.use(express.json());

app.set('view engine', 'ejs');
app.set('trust proxy', 1);

app.use((req, res, next) => {
  if(db.initialised) return next();
  res.status(404).send('DB is initialising ...');
})

const sessionStore = new MySQLStore({
  host: DB_HOST,
	port: DB_PORT,
	user: DB_USER,
	password: DB_PASSWORD,
  database: DB_DATABASE,
  clearExpired: true,
  connectionLimit: 10,
});

app.use(session({
  secret: APP_SECRET,
  cookie: {
    secure: true,
    maxAge: APP_COOKIE_EXPIRE,
    sameSite: 'none',
    expiration: 60*1000*60, // 1h
    clearExpired: true,
    httpOnly: true,
  },
  store: sessionStore,
  saveUninitialized: false,
  resave: false,
  unset: 'destroy'
}));


const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    cb(null, UPLOAD_PATH)
  },
  filename: function (req, file, cb) {
    cb(null, (Math.random()*2**52).toString(16) + '-' + Date.now())
  }
})

const upload = multer({ storage, limits:{fileSize: 1024 * APP_MAX_FILE_SIZE} })

const csrfmw = csrf({ cookie: false })


app.get('/', csrfmw, redirectLogin, async (req,res)=>{
  res.render('index', {_csrf: req.csrfToken(), session:req.session.data})
});

app.get('/login', csrfmw, (req, res) => {
  const e = (typeof req.query.e === 'string' && parseInt(req.query.e)) || -1;
  let error = false;
  switch(e){
    case 1:
      error = 'Please log in';
      break;
    case 2:
      error = 'Invalid session';
      break;
    case 3:
      error = 'User created successfully, please log in';
  }
  res.render('login', {_csrf: req.csrfToken(), error});
});

app.get('/register', csrfmw, (req, res) => {
  res.render('register', {_csrf: req.csrfToken()})
})

app.get('/logout', (req, res) => {
  req.session.destroy(()=>{
    res.redirect('/login');
  });
})

app.get('/report', (req, res) => {
  res.render('report');
})

function genTimestamp(){
  return Math.floor(Date.now()/FILECOMP_COOKIE_EXPIRE)*FILECOMP_COOKIE_EXPIRE;
}

function genId(){
  return crypto.randomInt(2**48-1);
}

function generateHash(...props){
  const hash_string = props.join(';;');
  return highwayhash.asUInt32High(RANDOM_BYTES, Buffer.from(hash_string));
}

function generateDomainHash(file_id, user_id, owner_id, timestamp){
  const doc_hash = generateHash(file_id, user_id, owner_id, timestamp) % MODULO_DOC;
  const user_hash = generateHash(user_id, owner_id, timestamp) % MODULO_USER;

  return `doc-${doc_hash}-${user_hash}`;
}

function verifyHash(hash_orig, ...props){
  const hash_new = generateHash(...props);
  return hash_new === parseInt(hash_orig);
}

async function verifyLogged(req, res, next){
  if(!req.session.data) return res.status(401).send('Unauthorized');
  const{username, uid} = req.session.data;
  const result = await db.existsUser(username, uid);
  if(Array.isArray(result) && result.length === 1) return next();
  return res.status(500).send('Invalid session');
}

async function redirectLogin (req, res, next){
  if(!req.session.data) return res.redirect('/login?e=1');
  const{username, uid} = req.session.data;
  const result = await db.existsUser(username, uid);
  if(Array.isArray(result) && result.length === 1) return next();
  return res.redirect('/login?e=2');
}

function isMedia(type){
  const ct = mime.getType(type) || "";
  return ct.startsWith('image/') ||
      ct.startsWith('audio/') ||
      ct.startsWith('video/') ||
      ct === 'application/pdf'
}


app.post('/register', csrfmw, async (req, res)=>{
  const {username, password} = req.body;
  if(!username || !password || typeof username != "string" || typeof password != "string"){
    return res.render('register', {_csrf: req.csrfToken(), error: 'Invalid form'});
  }
  if(username.length > 15) {
    return res.render('register', {_csrf: req.csrfToken(), error: 'Username too long. Max 15 characters'})
  };
  if(password.length > 30) {
    return res.render('register', {_csrf: req.csrfToken(), error: 'Password too long. Max 30 characters'});
  }
  const result = await db.register(username, password);

  if(result && result.affectedRows === 1) return res.redirect('/login?e=3');
  if(result && result.affectedRows === 0) return res.render('register', {_csrf: req.csrfToken(), error: 'The user already exists'});
  res.render('register', {_csrf: req.csrfToken(), error: 'Error while creating the user'});
});

app.post('/login', csrfmw, async (req, res) => {
  const {username, password} = req.body;
  if(!username || !password || typeof username != "string" || typeof password != "string"){
    return res.send("error");
  };
  const result = await db.login(username, password);
  if(result === "Error") return res.render('login', {_csrf: req.csrfToken(), error: "An unexpected error has occurred"});
  if(result.length === 1){
    const {name: username, id: uid} = result[0];
    req.session.data = {
      username,
      uid
    }
    await new Promise(resolve => {
        req.session.save( err => {
          resolve();
      });
    });
    return res.redirect('/');
  }
  res.render('login', {_csrf: req.csrfToken(), error: 'Invalid username or password'});
});

app.post('/file/share', csrfmw, verifyLogged, async (req, res) => {
  const user_id = req.session.data.uid;
  const file_id = parseInt(req.body.file_id);

  if(file_id === ADMIN_FILE_ID) return res.status(403).send("Did you want to share admin's file??");

  let to_list = req.body.to;
  if(isNaN(file_id)) return res.status(404).send('Invalid file id');
  if(!Array.isArray(to_list)) return res.status(404).send('Invalid list of ids');
  to_list = to_list.map(e=>parseInt(e)).filter(e=>!isNaN(e));
  if(to_list.length === 0) return res.status(404).send('Invalid list of ids');

  if(to_list.length > APP_SHARE_LIMIT){
    return res.status(404).send(`Too many ids. Limit is ${SHARE_LIMIT}`);
  }


  const file_db = await db.getFile(file_id);
  if(file_db === "Error" || !Array.isArray(file_db)) return res.status(500).send('Unexpected error');

  if(file_db[0].owner !== user_id) return res.status(403).send("Unauthorized for the action");

  const result = await db.shareFile(file_id, to_list, user_id);
  if(result === "Error") return res.status(500).send('Unexpected error');
  res.send('ok');
})

app.post('/upload', verifyLogged, upload.single('file'), csrfmw, async (req, res) => {
  const id = req.session.data.uid;
  const file = req.file;
  const public = req.body.visibility === 'public';
  if(file){
    const result = await db.addFile(id, file.originalname, file.path, file.size, public)
    if(result !== "Error") return res.redirect('/#file-'+result);
  }
  res.status(500).send('Error while uploading the file');
});

app.get('/user/files', verifyLogged, async (req, res) => {
  const user_id = req.session.data.uid;
  const files = await db.getFiles(user_id);
  if(files === "Error" || !Array.isArray(files)) return res.status(500).send("Unexpected Error");

  const result = [];

  for(let file of files){
    result.push({
      id: file.id,
      name: file.name,
      owner: file.owner,
      isPublic: file.public,
      isMedia: isMedia(file.name),
      size: file.size,
      docId: generateDomainHash(file.id, user_id, file.owner, genTimestamp())
    })
  }

  res.json(result);
});



app.get('/file', verifyLogged, async (req, res) => {
  const user_id = req.session.data.uid;
  const file_id = parseInt(req.query.id);
  if(isNaN(file_id)) return res.status(404).send('Please specify :id: parameter')

  let fileDb = await db.getFile(file_id);
  if(fileDb === "Error") return res.status(500).send('Unexpected error');
  if(!Array.isArray(fileDb) || fileDb.length !== 1) return res.status(404).send("File not found");

  const {owner:owner_id, public} = fileDb[0];
  const timestamp = genTimestamp();
  const doc_hash = generateDomainHash(file_id, user_id, owner_id, timestamp);
  let nonce = 0;

  if(typeof req.query.nonce === 'string' && typeof req.query.sgn === 'string'){
    const _nonce = parseInt(req.query.nonce);
    const _sgn = parseInt(req.query.sgn);
    if(generateHash(_nonce, user_id) === _sgn){
      nonce = _nonce;
    }
  }

  const url_hash = generateHash(doc_hash, nonce, file_id, user_id, owner_id, timestamp);

  let port = new URL('https://'+req.headers.host).port;
  port = port?':'+port:'';

  const preview = req.query.preview ? '?preview=1': '';
  const file_url = `//${doc_hash}.${APP_2DOMAIN}${port}/${url_hash}/${nonce}/${timestamp}/${owner_id}/${user_id}/${file_id}${preview}`

  if(user_id === owner_id || public === 1) return res.redirect(file_url);

  const isShared = await db.isSharedFile(file_id, user_id);
  if(isShared === 'Error' || !Array.isArray(isShared)) return res.status(500).send('Unexpected error');

  if(isShared.length === 1) return res.redirect(file_url);
  return res.status(403).send('Unauthorized');
});


app.post('/report', async (req, res) => {
  const file_id = req.body.fileid;

  if(typeof file_id !== 'string'){
    return res.send('Invalid type for fileid');
  }
  if(file_id.length > 30) {
    return res.send('Too long fileid!')
  }

  const client = net.Socket();
  client.connect(XSSBOT_PORT, XSSBOT_DOMAIN);
  client.on('data', data => {
    let msg = data.toString().trim();
    if(msg == "Please send me URL to open."){
      const visit_url = `https://${APP_DOMAIN}/file?id=${file_id}`;
      client.write(visit_url+'\n');
      client.destroy();
    }
    console.log(msg);
  });
  res.send('reported');
});

app.use((error, req, res, next) => {
  console.error(error);
  return res.status(500);
});

/* FileComp */

filecomp.use(cookieParser());

function parseNonce(cookie, user_id){
  const [nonce, sgn] = String(cookie).split('.').map(e=>parseInt(e));
  if(sgn === generateHash(nonce, user_id)) return nonce;
  return NaN;
}

filecomp.get('/:url_hash(\\d+)/:nonce(\\d+)/:timestamp(\\d+)/:owner_id(\\d+)/:user_id(\\d+)/:file_id(\\d+)', async (req, res, next) => {
  const {url_hash, nonce,timestamp,file_id,owner_id,user_id} = req.params;

  if(Date.now() - (parseInt(timestamp)||0) > FILECOMP_COOKIE_EXPIRE*2) {
    return res.status(404).send("URL expired");
  }

  const doc_hash = req.hostname.match(/^doc-\d+-\d+/)?.[0];

  let port = new URL('https://'+req.headers.host).port;
  port = port?':'+port:'';

  const preview = req.query.preview? '&preview=1' : '';

  const file_url = `//${APP_DOMAIN}${port}/file?id=${file_id}${preview}`

  if(!verifyHash(url_hash, doc_hash, nonce, file_id, user_id, owner_id, timestamp)){
    return res.status(500).send('Malformed URL');
  }

  const cookie_nonce = parseNonce(req.cookies.nonce, user_id);

  if(isNaN(cookie_nonce)){
    const new_nonce = genId();
    const sgn = generateHash(new_nonce,user_id);
    res.cookie('nonce', `${new_nonce}.${sgn}`, {
      maxAge: FILECOMP_COOKIE_EXPIRE,
      domain: APP_2DOMAIN,
      secure: true,
      sameSite: 'none',
      httpOnly: true
    });
    return res.redirect(file_url+`&nonce=${new_nonce}&sgn=${sgn}`)
  }

  if(cookie_nonce !== parseInt(nonce)){
    const sgn = generateHash(cookie_nonce,user_id);
    return res.redirect(file_url+`&nonce=${cookie_nonce}&sgn=${sgn}`)
  };

  let fileDb = await db.getFile(file_id);
  if(fileDb === "Error") return res.status(500).send('Unexpected error');
  if(!Array.isArray(fileDb) || fileDb.length !== 1) return res.status(404).send("File not found");

  fileDb = fileDb[0];

  const file_mime = mime.getType(fileDb.name) || 'binary/octet-stream';
  const content_disp = req.query.preview === '1' && isMedia(fileDb.name) ?
  `inline; filename="${fileDb.name}"`: `attachement; filename="${fileDb.name}"`

  const fileOptions = {
    dotfiles: 'deny',
    headers: {
      'Content-Disposition': content_disp,
      'Content-type': file_mime
    }
  }
  res.sendFile(fileDb.path, fileOptions, err => {
    if(err){
      res.status(404).send('Error while fetching the file');
    }
  });
})

filecomp.get('*', (req, res) => {
  res.set('content-type', 'text/plain');
  res.status(404).send(
`\
Invalid URL format. The URL should be in the below form.
    doc-<doc_hash>-<user_hash>.${APP_2DOMAIN}/<signature>/<nonce>/<timestamp>/<owner_id>/<user_id>/<file_id>
where <doc_hash>  ~ HASH(SECRET || <file_id> || <user_id> || <owner_id> || <timestamp>) MODULO ${MODULO_DOC},
and   <user_hash> ~ HASH(SECRET || <user_id> || <owner_id> || <timestamp>) MODULO ${MODULO_USER}

nonce cookie is signed by ~ HASH(SECRET || <random_int> || <user_id>)
`)
})

filecomp.use((error, req, res, next) => {
  console.error(error);
  return res.status(500);
});

const httpServer = https.createServer({
  key: fs.readFileSync(__dirname + '/privkey.pem', 'utf8'),
  cert: fs.readFileSync(__dirname + '/fullchain.pem', 'utf8')
}, server)


httpServer.listen(LISTEN_PORT, ()=>{
    console.log(`The app is listening on localhost:${LISTEN_PORT}`);
});

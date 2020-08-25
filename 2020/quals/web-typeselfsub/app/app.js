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

const fs = require('fs');
const mysql = require('mysql');
const express = require('express');
const cookieSession = require('cookie-session');
const qs = require('querystring');
const cookieParser = require('cookie-parser');
const bodyParser = require('body-parser');
const puppeteer = require('puppeteer');
const request = require('request');


const mikeFlag = "CTF{self-xss?-that-isn't-a-problem-right...}"
const chatUserUsername = "mike"

const ctfDomain = "typeselfsub.web.ctfcompetition.com"
const ctfChatDomain = "typeselfsub-support.web.ctfcompetition.com"
//testDomain = "typeselfsub-mf89fg9xmybn-dot-ctf-web-kuqo48d.ew.r.appspot.com"
const testDomain = "typeselfsub-mf89fg9xmybn-dot-ctf-web-kuqo48d.appspot.com"
const testChatDomain = "typeselfsub-support-mkv40xfl56s-dot-ctf-web-kuqo48d.appspot.com"


const {
  v4: uuidv4
} = require('uuid');

const app = express();
app.set('trust proxy', 1) // trust first proxy

app.set('view engine', 'ejs');
app.set('strict routing', true);

/* strict routing to prevent /note/ paths etc. */
app.set('strict routing', true)
app.use(cookieParser());

/* secure session in cookie */
app.use(cookieSession({
  name: 'session',
  sameSite:process.env.DEV ? undefined: 'none',
  secure:process.env.DEV? undefined: true,
  keys: ['jsdf0988g8g8g88gjalsidifiij9v8m2q94vn97n97mv92n397v629v7m987zsmx9dvs836wmvjxchb,mncixccyw9q3764109aos8ufvzxc7x'],
}));

app.use(bodyParser.urlencoded({
  extended: true
}))

app.use(function(req, res, next) {
  dom = req.headers.host;
  if(dom == "localhost:8088") {
    res.locals.chathost = "localhost:9989";
  } else if(dom == ctfDomain) {
    res.locals.chathost = ctfChatDomain
  } else if(dom == testDomain) {
    res.locals.chathost = testChatDomain
  } else {
    res.locals.chathost = "this is an error, contact organisers"
  }
  if(req && req.session && req.session.username) {
    res.locals.username = req.session.username
    res.locals.address = req.session.address
    res.locals.flag = req.session.flag
  } else {
    res.locals.username = false
    res.locals.flag = false
    res.locals.address = false
  }
  next()
});

/* server static files from static folder */
app.use('/static', express.static('static'))

app.use(function( req, res, next) {
  if(req.get('X-Forwarded-Proto') == 'http') {
      res.redirect('https://' + req.headers.host + req.url)
  } else {
    if (process.env.DEV) {
      return next()
    } else  {
    return next()
    }
  }
});
// MIDDLEWARE ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

/* csrf middleware, csrf_token stored in the session cookie */
const csrf = (req, res, next) => {
  const csrf = uuidv4();
  req.csrf = req.session.csrf || uuidv4();
  req.session.csrf = csrf;
  res.locals.csrf = csrf;

  nocache(res);

  if (req.method == 'POST' && req.csrf !== req.body.csrf) {
    return res.render('index', {error: 'Invalid CSRF token'});
  }

  next();
}

/* disable cache on specifc endpoints */
const nocache = (res) => {
  res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate');
  res.setHeader('Pragma', 'no-cache');
  res.setHeader('Expires', '0');
}

/* auth middleware */
const auth = (req, res, next) => {
  if (!req.session || !req.session.username) {
    return res.render('index', {error:"You must be logged in to access that"});
  }
  next()
}

// ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~`
app.get('/logout', (req, res) => {
  req.session = null;
  res.redirect('/');
});


app.get('/chat', csrf, auth, (req, res) => {
  /*
  if(! req.session.isPaid) {
    res.render('chat',{error:"Only premium members can chat"});
  } else {
    res.render('chat',);
  }
  */
  res.render('chat',);
});

app.post('/initiateChat', auth, (req, res) => {

  const reason = req.body['reason'];
  if(typeof reason != 'string') {
    res.json(500, {error:'error'});
    return;
  }

  const encodedReason = qs.escape(reason);
  const url = req.protocol + '://' + req.headers.host +'/asofdiyboxzdfasdfyryryryccc?username=mike&password=j9as7ya7a3636ncvx&reason=' + encodedReason;
  console.log(url);



  (async () => {
  const browser = await puppeteer.launch();
  const page = await browser.newPage();
  await page.goto(url, {waitUntil: 'networkidle2',timeout:10000});
  await browser.close();
  })();

  res.json({uuid:uuidv4(),reason:reason});
});


app.get('/', csrf, (req, res) => {
  res.render('index');
});

app.get('/about', (req, res) => {
  res.render('about');

});
app.get('/me', auth, (req, res) => {
  res.render('profile');
});

app.post('/me', auth, (req, res) => {
  const addr = req.body['address']+'';
  const oldUsername = req.session.username;

  if(oldUsername.toLowerCase() == "mike") {
    res.render('profile',{error: `Sorry, premium accounts can't be changed for security reasons.`});
    return;
  }

  const con = DBCon();

  const sql = 'update users set address = ? where username = ?';

  con.query(sql, [addr, oldUsername], function(err, qResult) {
    con.destroy()
    if(err) {
      res.render('profile',{error: `An error occurred: ${err}`});
    } else {
      req.session.username = oldUsername
      res.locals.username = oldUsername
      req.session.address = addr
      res.locals.address = addr
      res.render('profile', {message:"Updated successfully!"});
    }
  });
});

app.get('/flag', csrf, auth, (req, res) => {
  res.render('premium')
});

app.get('/register', (req, res) => {
  res.render("register")
});
app.post('/register', (req, res) => {
  const u = req.body['username'];
  const p = req.body['password'];

  const con = DBCon();

  sql = `insert into users (username, password, address) values (?, ?, '')`;
  con.query(sql, [u, p], function(err, qResult) {
    con.destroy()
    if(err) {
      res.render('register',{error: `Unexpected error: ${err}`});
    } else {
      res.render("register",{message:"User created successfully!"});
    }
  });
});

app.get('/login', (req, res) => {
  res.render('login');
});

/* a hack to make the xss bot work */
app.get('/asofdiyboxzdfasdfyryryryccc', (req, res) => {

  const u = req.query['username'];
  const p = req.query['password'];
  const payload = req.query['reason'];
  console.log(p,u,payload);
  const a = "Don't use this";
  if( typeof u != "string" || u != "mike" || typeof p != "string"
      || p != "j9as7ya7a3636ncvx" || typeof payload != "string") {
    res.status(500).send(a);
    return
  }

   req.session.username = "Mike"
   req.session.flag = mikeFlag
   req.session.address = ""
   res.render('chatadmin',{message:payload})
});

app.post('/login', (req, res) => {
  const u = req.body['username'] + '';
  const p = req.body['password'] + '';

  const con = DBCon()

  var sql = 'Select * from users where username = ? and password = ?';
  con.query(sql, [u, p], function(err, qResult) {
    con.destroy()
    if(err) {
      res.render('login', {error: `Unknown error: ${err}`});
    } else if(qResult.length) {
      let username = qResult[0]['username'];
      let addr = qResult[0]['address']
      let flag = "<span class=text-danger>Only the chat user's account has flag</span>";

      if(username.toLowerCase() == chatUserUsername) {
        res.render('login', {error: "This account cannot be logged into.\nMaybe the person on the other side of chat is already logged in with this account..."});
        return
      }
      req.session.username = username
      req.session.address = addr
      req.session.flag = flag
      res.redirect('/me');
    } else {
      res.render('login', {error: "Invalid username or password"})
    }
  });
});

function DBCon() {
  var con = null;

  if (process.env.DEV) {
      con = mysql.createConnection({
        host: 'localhost',
        user: 'ctf',
        password: 'kajsdfouyhsdfhl',
        database: 'ctf',
        insecureAuth: true
      });
  } else {
      con = mysql.createConnection({
        socketPath: `/cloudsql/${process.env.INSTANCE_CONNECTION_NAME}`,
        user: process.env.DB_USER,
        password: process.env.DB_PASS,
        database: process.env.DB_NAME
      });
  }
  con.connect();

  return con;
}

app.listen(process.env.PORT || 8088)

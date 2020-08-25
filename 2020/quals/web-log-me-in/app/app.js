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
const cookieParser = require('cookie-parser');
const bodyParser = require('body-parser');
const {CloudTasksClient} = require('@google-cloud/tasks');
const request = require('request');

const flagValue = "CTF{a-premium-effort-deserves-a-premium-flag}"
const targetUser = "michelle"

const {
  v4: uuidv4
} = require('uuid');

const app = express();
app.set('view engine', 'ejs');
app.set('strict routing', true);

/* strict routing to prevent /note/ paths etc. */
app.set('strict routing', true)
app.use(cookieParser());

/* secure session in cookie */
app.use(cookieSession({
  name: 'session',
  //sameSite:process.env.DEV ? undefined: 'lax',
  //secure:process.env.DEV? undefined: true,
  keys: ['laskdjf9as8dfj9238jf2ljaa9o8nbv9n92q7649v27qn989v8m2q94vn97n97mv92n397v629v7m987zsmx9dvs836wmvjxchb,mncixccyw9q3764109aos8ufvzxc7x'],
}));

app.use(bodyParser.urlencoded({
  extended: true
}))

app.use(function(req, res, next) {
  if(req && req.session && req.session.username) {
    res.locals.username = req.session.username
    res.locals.flag = req.session.flag
  } else {
    res.locals.username = false
    res.locals.flag = false
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
  //console.log(req.session);

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


app.get('/', csrf, (req, res) => {
  res.render('index');
});

app.get('/about', (req, res) => {
  res.render('about');

});
app.get('/me', auth, (req, res) => {
  res.render('profile');
});

app.get('/flag', csrf, auth, (req, res) => {
  res.render('premium')
});

app.get('/login', (req, res) => {
  res.render('login');
});

app.post('/login', (req, res) => {
  const u = req.body['username'];
  const p = req.body['password'];

  const con = DBCon();

  const sql = 'Select * from users where username = ? and password = ? order by id';
  con.query(sql, [u, p], function(err, qResult) {
    con.destroy()
    if(err) {
      res.render('login', {error: `Unknown error: ${err}`});
    } else if(qResult.length) {
      const username = qResult[0]['username'];
      let flag;
      if(username.toLowerCase() == targetUser) {
        flag = flagValue
      } else{
        flag = "<span class=text-danger>Only Michelle's account has the flag</span>";
      }
      req.session.username = username
      req.session.flag = flag
      res.redirect('/me');
    } else {
      res.render('login', {error: "Invalid username or password"})
    }
  });
});

app.get('/wedontwantuserstofindthisendpoint', (req, res) => {
  const con = mysql.createConnection({
    socketPath: `/cloudsql/${process.env.INSTANCE_CONNECTION_NAME}`,
    user: 'root',
    password: '',
    multipleStatements: true
  });
  con.connect();

  con.query(`CREATE USER '${process.env.DB_USER}'@'%' IDENTIFIED BY '${process.env.DB_PASS}';`, (err, res) => {
    if (err)
      console.log(err);
  });

  con.query(`GRANT ALL ON ${process.env.DB_NAME}.* TO '${process.env.DB_USER}'@'%';`, (err, res) => {
    if (err)
      console.log(err);
 });

  con.query(`CREATE DATABASE ${process.env.DB_NAME};`, (err, res) => {
    if (err)
      console.log(err);
  });

  con.changeUser({database: process.env.DB_NAME}, (err) => {
    if (err)
      console.log(err);
  });

  const sql = fs.readFileSync('db.sql').toString();
  con.query(sql, (err, res) => {
    if (err)
      console.log(err);
  });

  res.end('ok');
});

function DBCon() {
  let con = null;

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

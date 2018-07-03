// Copyright 2017, Google, Inc.
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//    http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

'use strict';

const express = require('express');
const bodyParser = require('body-parser');
const images = require('../lib/images');
const crypto = require('crypto');
const auth = require('../lib/auth');
const userModel = require('./model-user');


function h(s) {
    const hash = crypto.createHash('sha256');
    hash.update(s+'');
    return hash.digest('hex');
}

const router = express.Router();

// Automatically parse request body as form data
router.use(bodyParser.urlencoded({ extended: false }));

router.use(auth.router);

// Set Content-Type for all responses for these routes
router.use((req, res, next) => {
  res.set('Content-Type', 'text/html');
  next();
});

router.get('/login', (req, res, next) => {
    res.render('user/login.pug', {
          user: {}
    });
});

router.get('/logout', auth.logout, (req, res) => {
  res.redirect('/');
});

router.post('/login', async (req, res, next) => {
    let data = req.body;

    let u = await userModel.get(h(data.name));

    if (!u || u.password !== h(data.password)) {
        res.status(403).send('Invalid login.');
        return;
    }

    req.user = u;
    next();

}, auth.required, (req, res, next) => {
    res.redirect('/');
});

router.get('/register', (req, res, next) => {
    res.render('user/reg.pug', {
          user: {}
    });
});

router.post('/register',
  images.multer.single('image'),
  images.sendUploadToGCS,
  async (req, res, next) => {
    try {
        let data = req.body;

        let u = await userModel.get(h(data.name));

        if (u) {
            res.status(400).send('User exists.');
            return;
        }

        if (req.file && req.file.cloudStoragePublicUrl) {
          data.image = req.file.cloudStoragePublicUrl;
        }

        if (data.name === 'admin') {
            res.status(503).send('Nope!');
            return;
        }

        data.age = data.age | 0;

        if (data.age < 18) {
            res.status(503).send('You are too young!');
            return;
        }

        data.password = h(data.password);

        userModel.update(h(data.name), data, () => {
            res.redirect('/');
        });
    } catch (e) {
        next(e);
    }
});



module.exports = router;

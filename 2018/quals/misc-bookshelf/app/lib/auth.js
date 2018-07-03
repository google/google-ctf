// Copyright 2018 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

const express = require('express')
const cookieParser = require('cookie-parser')
const config = require('../config')
const bwt = require('../lib/bwt')(config.get('AUTH'));
const crypto = require('crypto');

const router = express.Router();
router.use(cookieParser());

function h(s) {
    const hash = crypto.createHash('sha256');
    hash.update(s+'');
    return hash.digest('hex');
}

function authRequired(req, res, next) {
  if (!req.user) {
    return res.redirect('/user/login');
  } else if (!req.cookies.auth) {
      res.cookie('auth', bwt.encode(req.user));
  }
  next();
}

function addTemplateVariables(req, res, next) {
  res.locals.profile = req.user;
  next();
}

function logout(req, res, next) {
    res.clearCookie('auth');
    next();
}

router.use((req, res, next) => {
    if (req.cookies.auth) {
        let user = bwt.decode(req.cookies.auth);
        if (user)
            req.user = user;
    }
    next();
});


module.exports = {
    required: authRequired,
    router,
    template: addTemplateVariables,
    logout
}

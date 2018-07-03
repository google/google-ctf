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

const crypto = require('crypto');
const userModel = require('./books/model-user');
const config = require('./config');

function h(s) {
    const hash = crypto.createHash('sha256');
    hash.update(s+'');
    return hash.digest('hex');
}

function getModel () {
  return require(`./books/model-${require('./config').get('DATA_BACKEND')}`);
}

function initBook() {
  getModel().update('5eab1600-b86e-4ebc-af0f-7d9f618c41c3',{
    title: 'FLAG',
    description: config.get('FLAG'),
    createdBy: 'admin',
    createdById: h('admin')
  }, (err) => {
    if (err) {
      console.error(err);
      throw err;
    }
  });
}

function initAdmin() {
  userModel.update(h('admin'), {
    name: 'admin',
    password: h(config.get('FLAG')),
  }, (err) => {
    if (err) {
      console.error(err);
      throw err;
    }
  });
}

initAdmin();
initBook();

module.exports = function() {
    initAdmin();
    initBook();
}

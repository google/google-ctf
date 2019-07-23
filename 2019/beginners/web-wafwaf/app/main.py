#!/usr/bin/python
#
# Copyright 2019 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import hashlib
import hmac
import random
import time
import os
from flask import Flask, abort, flash, make_response, request, render_template, redirect, url_for, g
import sqlite3


# 1" union select b,d from (SELECT 1 as a, 2 as b, 3 as c, 4 as d where false union select * from users) where a between 1 and 1 /*

app = Flask(__name__)
app.secret_key = os.urandom(128)

BLACKLIST = ['#', '<', '>', '=', '%', '-']
BLACKLIST_WORDS = ['or', 'is', 'like', 'join', '0', 'limit', 'char']


def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(':memory:')
        with app.app_context():
            db.cursor().execute('CREATE TABLE users (id INTEGER PRIMARY KEY, name TEXT, population INT, secret_password TEXT);')
            with app.open_resource('schema.sql', mode='r') as f:
                db.cursor().executescript(f.read())
            db.commit()
    return db

@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()

def query_db(query, args=(), one=False):
    cur = get_db().execute(query, args)
    rv = cur.fetchall()
    cur.close()
    return (rv[0] if rv else None) if one else rv

def check_parameter(name):
  for c in BLACKLIST:
    if c in name:
      return False
  for w in BLACKLIST_WORDS:
    if w in name:
      return False
  return True

@app.route('/', methods=['GET', 'POST'])
def index_page():
  if request.method == 'GET':
    return render_template('index.html')
  else:
    name = request.form.get('name')
    if name is None:
      err = 'Please specify a name'
      return render_template('index.html', err=err)

    name = name.lower()

    if check_parameter(name) is False:
      err = 'Please do not hack the system, thanks.'
      return render_template('index.html', err=err)
    q = 'select name, population from users where name = "%s";' % name
    result = query_db(q, one=True)
    if result is None:
      err = 'No result for ' + name
      return render_template('index.html', err=err)
    return render_template('index.html', result=result)


if __name__ == '__main__':
  app.run()

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
import logging
import random
import time
import os
import re
import urllib.parse

from flask import Flask, abort, flash, make_response, request, render_template, redirect, url_for, g, jsonify
from flask_batch_with_ct import batch as fl_batch

from google.cloud import tasks_v2

app = Flask(__name__)
app.secret_key = os.urandom(128)



@app.route("/batch", methods=["POST"])
def batch():
  headers, code, body = fl_batch()
  return headers, code, body

@app.route("/wish", methods=["POST"])
def wish():
    wish_item = request.json
    if "wish" in wish_item:
      return jsonify({"wish": random.choice(["granted", "not_granted"])})
    else:
      return jsonify({"wish": "No wish"})

@app.route('/', methods=['GET'])
def index_page():
  if request.method == 'GET':
    return render_template('index.html')

@app.route("/genie", methods=["POST"])
def confirmation():
    url = request.form.get('url')

    logging.debug(url)

    client = tasks_v2.CloudTasksClient()
    parent = client.queue_path('ctf-web-kuqo48d', 'europe-west1', 'xss')
    client.create_task(parent, {
      'app_engine_http_request': {
          'http_method': 'POST',
          'relative_uri': '/submit',
          'app_engine_routing': {
              'service': 'uxssbot'
          },
          'headers': {
            'Content-Type': 'application/x-www-form-urlencoded'
          },
          'body': urllib.parse.urlencode({'url': url, 'service': 'genie'}).encode()
        }
    })

    return render_template('confirmation.html')

if __name__ == '__main__':
  app.run(debug=True)

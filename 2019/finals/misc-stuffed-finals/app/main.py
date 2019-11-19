#!/usr/bin/python2

# Copyright 2019 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from __future__ import absolute_import
from __future__ import division
from __future__ import print_function

import logging

import flask

app = flask.Flask(__name__)

with open('bomb.br', 'rb') as bomb_file:
  bomb_data = bomb_file.read()

def AllowsBrotli(headers):
  h = headers.get('Accept-Encoding')
  if not h:
    return False
  for accept in h.split(','):
    v, _, _ = accept.strip().partition(';')
    if v == 'br':
      return True
  return False

@app.route('/')
def hello():
  forwarded_header = flask.request.headers.get('X-Forwarded-Proto')
  if forwarded_header is not None and forwarded_header != 'https':
    # Firefox only supports brotli on https, so make sure https.
    # Also it's good for security.
    # We only do this redirect when running on actual appengine (determined by
    # presence of forwarded header) to avoid having to use https when running
    # locally.
    # Don't bother including path or query, because we don't use those.
    # Don't include port because http->https likely means a port change.
    return flask.redirect('https://' + flask.request.host)

  if AllowsBrotli(flask.request.headers):
    resp = flask.make_response(bomb_data)
    resp.headers['Content-Encoding'] = 'br'
    return resp
  return flask.make_response(
      ("To avoid a repeat of last month's bandwidth bill, we only support "
       "browsers that can understand Brotli compression. Supported browsers "
       "include Chrome, Firefox, Edge, Safari, and Opera.\n",
       406))  # Unacceptable!

if __name__ == '__main__':
  # This is used when running locally. Gunicorn is used to run the
  # application on Google App Engine. See entrypoint in app.yaml .
  app.run(host='127.0.0.1', port=8080, debug=True)

#!/usr/bin/python
#
# Copyright 2018 Google LLC
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

"""WebAsm challenge."""

import logging
import json
import os
import jinja2
import urllib
import webapp2

from google.appengine.api import app_identity
from google.appengine.api import urlfetch

jinja_environment = jinja2.Environment(
    loader=jinja2.FileSystemLoader(os.path.dirname(__file__)),
    extensions=['jinja2.ext.autoescape'],
    autoescape=True)

CHALLENGE_NAME = os.environ.get('CHALLENGE_NAME', 'asm')

class MainPage(webapp2.RequestHandler):

  def get(self):
    flag = self.request.get('flag', 'cL1ck_subm1t_t0_g3t_th3_r34L_fL4g')
    debug = self.request.get('debug')
    program = self.request.get('program')
    challenge = self.request.get('challenge')
    template = jinja_environment.get_template('index.html')
    if debug or program or challenge:
      template = jinja_environment.get_template('debug.html')
    logs = self.request.get('logs')
    self.response.out.write(
        template.render(
            flag=flag,
            program=program,
            challenge=json.dumps(challenge),  # written in JS context
            logs=logs.split('|')))


class Submit(webapp2.RequestHandler):

  def post(self):
    flag = 'r3m0v3_th3_c0mm4s_plz_kthxbye'
    url = 'http://%s/?%s'%(
        self.request.host,
        urllib.urlencode({
            'flag': flag,
            'challenge': self.request.get('challenge'),
            'program': self.request.get('program')
        })
    )
    result = urlfetch.fetch(
        'https://uxssbot-dot-%s.appspot.com/submit?%s'%(
            app_identity.get_application_id(),
            urllib.urlencode({'url': url, 'service':'webasm', 't': os.environ.get('TOKEN', 'missing_token')})
        ), deadline=30)
    logging.info('Result: %s', result.content)
    response = json.loads(result.content)
    messages = []
    for l in response:
      try:
        arguments = l['console']['args']
        location = l['console']['stackTrace']['callFrames'][-1]['url']
        if len(arguments) > 0:
          message = arguments[0]
          if location == url and 'value' in message:
            messages.append(message['value'])
      except:
        logging.exception('logging error: %s', result.content)
        messages.append('Error parsing response from server')
    self.redirect('/?logs=%s' % '|'.join(messages))


application = webapp2.WSGIApplication(
    [
        ('/', MainPage),
        ('/submit', Submit),
    ], debug=False)

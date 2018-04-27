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

import urllib
import os
import json
import httplib

import webapp2
from google.appengine.api import taskqueue

CAPTCHA_SECRET = '6LdOfSEUAAAAABSc1i6ayKqr_wWRZxn7TPT-r3vp'
captcha_api = httplib.HTTPSConnection('www.google.com')

class SubmitHandler(webapp2.RequestHandler):
  def get(self):
    captcha = self.request.get('g-recaptcha-response')
    if not captcha:
      return self.response.set_status(403)

    captcha_api.request(
        'POST',
        'https://www.google.com/recaptcha/api/siteverify',
        urllib.urlencode({
          'secret': CAPTCHA_SECRET,
          'response': captcha,
          'remoteip': self.request.remote_addr
        })
    )
    captcha_res = json.loads(captcha_api.getresponse().read())
    if captcha_res['success'] != True:
      return self.response.set_status(403)

    url = self.request.host_url + '/#' + urllib.quote(self.request.get('html'))
    taskqueue.add(
        url='/submit',
        target='uxssbot',
        params={'url': url, 'service': 'sanitizer'},
        retry_options=taskqueue.TaskRetryOptions(task_retry_limit=1)
    )

    return self.response.write('Thanks, your solution is now submitted, we\'ll take a look soon')

app = webapp2.WSGIApplication([('/submit', SubmitHandler)], debug=False)

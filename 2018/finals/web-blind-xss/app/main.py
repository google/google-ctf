# Copyright 2018 Google LLC
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

import os
import urllib

import jinja2
import webapp2
from webapp2_extras import sessions
from google.appengine.api import taskqueue

JINJA_ENVIRONMENT = jinja2.Environment(
    loader=jinja2.FileSystemLoader(os.path.dirname(__file__)),
    extensions=['jinja2.ext.autoescape'],
    autoescape=True
)

FLAG = 'CTF{D3F3nsiV3_JS_4Ev3r}'

class MainPage(webapp2.RequestHandler):
  def get(self):
    template = JINJA_ENVIRONMENT.get_template('index.html')
    self.response.write(template.render({
        'payload': 'location = "https://example.com"; /* This should work */'
    }))

  def post(self):
    payload = self.request.POST.get('payload')
    victim_url = (self.request.host_url + '/victim?' +
                  urllib.urlencode({'payload': payload}))
    print 'Visiting', victim_url
    task = taskqueue.add(
        url='/submit',
        target='uxssbot',
        params={'url': victim_url, 'service': 'blindxss'},
        retry_options=taskqueue.TaskRetryOptions(task_retry_limit=1)
    )
    template = JINJA_ENVIRONMENT.get_template('index.html')
    self.response.write(template.render({'payload': payload}))

class VictimHandler(webapp2.RequestHandler):
  def get(self):
    if self.request.cookies.get('flag') != FLAG:
        return self.response.write('Access denied, no valid flag cookie found.')
    template = JINJA_ENVIRONMENT.get_template('victim.html')
    self.response.write(template.render({}))

app = webapp2.WSGIApplication([
    ('/', MainPage),
    ('/victim', VictimHandler),
], debug=False)

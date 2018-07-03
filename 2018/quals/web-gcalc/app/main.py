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

import cgi
import json
import logging
import os
import re
import urllib
import urllib2
import webapp2

from google.appengine.api import taskqueue


RECAPTCHA_PRIVKEY = os.environ.get('RECAPTCHA_PRIVKEY', '')

class MainPage(webapp2.RequestHandler):
    def get(self):
        host = 'https://sandbox-gcalc2.web.ctfcompetition.com'

        self.response.headers['Content-Security-Policy'] = "default-src 'self'; frame-src {0}/".format(host);
        self.response.headers['X-Frame-Options'] = "DENY";
        html = open('index.html').read()

        qs = self.request.query_string

        html = html.replace('%QUERY_STRING%', cgi.escape(qs, True))
        html = html.replace('%HOST%', cgi.escape(host, True))

        self.response.write(html)

class ReportPage(webapp2.RequestHandler):
    def post(self):
        qs = ''
        try:
            body = json.loads(self.request.body)
            qs = urllib.urlencode({'expr': body.get('expr'), 'vars': body.get('vars')})
        except ValueError:
            logging.exception('report')
            self.abort(500)

        recaptcha_response = urllib.urlencode({
            'secret': RECAPTCHA_PRIVKEY,
            'response': body.get('recaptcha')
        })

        res = json.loads(urllib2.urlopen(url='https://www.google.com/recaptcha/api/siteverify', data=recaptcha_response).read())

        if not res.get('success'):
            self.abort(403)

        if qs:
            url = '%s/?%s' % (self.request.host_url.replace('sandbox-','') , qs)
            logging.debug(url)

            taskqueue.add(
                url='/submit',
                target='uxssbot',
                params={'url': url, 'service': 'gcalc'},
                retry_options=taskqueue.TaskRetryOptions(task_retry_limit=1))
            self.response.write('ok')


app = webapp2.WSGIApplication([
    ('/', MainPage),
    ('/report', ReportPage),
], debug=False)

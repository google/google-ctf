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

import base64
import jinja2
import json
import logging
import os
import urllib
import urllib2
import uuid
import webapp2

from config import *
from google.appengine.ext import ndb
from google.appengine.api import taskqueue

RECAPTCHA_SITE_KEY = os.environ['RECAPTCHA_SITE_KEY']
RECAPTCHA_PRIVATE_KEY = os.environ['RECAPTCHA_PRIVATE_KEY']

DATASTORE_NAMESPACE = 'pastetastic'

JINJA_ENVIRONMENT = jinja2.Environment(
    loader=jinja2.FileSystemLoader(os.path.dirname(__file__)),
    extensions=['jinja2.ext.autoescape'],
    autoescape=True)

CREATE_TEMPLATE = JINJA_ENVIRONMENT.get_template('templates/create.html')
REPORT_SUCCESS_TEMPLATE = JINJA_ENVIRONMENT.get_template('templates/report_success.html')
VIEW_TEMPLATE = JINJA_ENVIRONMENT.get_template('templates/view.html')
SANDBOX_TEMPLATE = JINJA_ENVIRONMENT.get_template('templates/sandbox.html')

STRICT_CSP = {
    'object-src': "'none'",
    'script-src': "'nonce-{nonce}' 'unsafe-eval' 'strict-dynamic' https: http:",
    'base-uri': "'none'",
}


class Paste(ndb.Model):
  name = ndb.StringProperty(indexed=False)
  lang = ndb.StringProperty(indexed=False)
  text = ndb.StringProperty(indexed=False)


class BaseHandler(webapp2.RequestHandler):

  def __init__(self, request, response):
    self.initialize(request, response)
    self.nonce = base64.b64encode(uuid.uuid4().bytes)

  def dispatch(self):
    super(BaseHandler, self).dispatch()
    self.response.headers['X-Content-Type-Options'] = 'nosniff'
    csp_policy = ('; '.join(
        ['{} {}'.format(k, STRICT_CSP[k]) for k in STRICT_CSP.keys()])
        .format(nonce=self.nonce))
    self.response.headers['Content-Security-Policy'] = csp_policy
    if self.response.status_int != 302:
      self.response.headers['Content-Type'] = 'text/html; charset=utf-8'


class Root(BaseHandler):

  def get(self):
    self.redirect('/create')


class Create(BaseHandler):

  def get(self):
    default_lang = coercePluginLang(self.request.get('lang'))
    self.response.write(CREATE_TEMPLATE.render({
        'nonce': self.nonce,
        'config': buildCreateConfig(default_lang),
        'lang': default_lang,
        'recaptcha_site_key': RECAPTCHA_SITE_KEY,
    }))

  def post(self):
    lang = self.request.get('lang')
    validatePluginLang(lang)
    id = uuid.uuid4().hex
    paste = Paste(
        id=id,
        namespace=DATASTORE_NAMESPACE,
        name=self.request.get('name'),
        lang=lang,
        text=self.request.get('text'))
    key = paste.put()
    self.redirect('/view/{}'.format(id))


class View(BaseHandler):

  def get(self, key):
    paste = ndb.Key(Paste, key, namespace=DATASTORE_NAMESPACE).get()
    if paste is None:
      self.abort(404)
      return
    config = buildViewConfig(paste.lang)
    self.response.write(VIEW_TEMPLATE.render({
        'id': paste.key.id(),
        'nonce': self.nonce,
        'config': config,
        'name': paste.name,
        'lang': paste.lang,
        'text': paste.text,
        'recaptcha_site_key': RECAPTCHA_SITE_KEY,
        'base_url': self.request.host_url
    }))


class Sandbox(BaseHandler):

  def get(self):
    self.response.write(SANDBOX_TEMPLATE.render({'nonce': self.nonce}))
    self.response.headers['Cache-Control'] = 'public, max-age=31536000'


class Report(BaseHandler):

  def post(self):
    recaptcha_response = urllib.urlencode({
        'secret': RECAPTCHA_PRIVATE_KEY,
        'response': self.request.get('g-recaptcha-response')
    })
    res = json.loads(urllib2.urlopen(url='https://www.google.com/recaptcha/api/siteverify', data=recaptcha_response).read())
    if not res.get('success'):
      self.abort(403)

    url = self.request.get('page', '')
    logging.debug(url)
    taskqueue.add(
        url='/submit',
        target='uxssbot',
        params={'url': url, 'service': 'pastetastic'},
        retry_options=taskqueue.TaskRetryOptions(task_retry_limit=1))
    self.response.write(REPORT_SUCCESS_TEMPLATE.render({
        'nonce': self.nonce,
    }))


app = webapp2.WSGIApplication([
    ('/', Root),
    ('/create', Create),
    ('/view/(.+)', View),
    ('/report', Report),
    ('/sandbox', Sandbox),
], debug=False)

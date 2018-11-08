#!/usr/bin/python
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
from flask import Flask, redirect, request, make_response, send_from_directory
from google.cloud import tasks_v2beta3
import logging
from urllib.parse import urlencode, quote_plus

client = tasks_v2beta3.CloudTasksClient()
parent = client.queue_path('ctf-web-kuqo48d', 'europe-west1', 'xss')
SECRET_URL = '917fh3h5721'

app = Flask(__name__, static_url_path='')
app.url_map.host_matching = (__name__ != '__main__')

@app.route('/', host="bountyplz-mitigator.web.ctfcompetition.com", methods=['GET', 'POST'])
def bountyplz():
  """Return XSS and BugBounty Form (for PoCs/xss bot)"""
  poc = request.form.get('poc', '')
  if poc.startswith("http"):
    task = {
        'app_engine_http_request': {
            'app_engine_routing': {
                'service': 'uxssbot',
            },
            'http_method': 'POST',
            'relative_uri': '/submit?%s'%urlencode({'service': 'mitigator', 'url': poc}, quote_via=quote_plus),
            'body': urlencode({'service': 'mitigator', 'url': poc}, quote_via=quote_plus).encode(),
        }
    }
    res = client.create_task(parent, task)
    logging.info('Created uxssbot task: ' + res.name)
    return """We have received your bug report."""
  return """
  <html>
  <script src='https://www.google.com/recaptcha/api.js'></script>
  <form method=post action=/>
  <div class="g-recaptcha" data-sitekey="6LfR1XUUAAAAAPGx2NejNMYImdoRW9PZLQcFtBN_"></div>
  <input type=url name=poc placeholder="PoC URL" value=%s>
  <input type=submit>
  </form>
  </html>"""%poc

@app.route('/' + SECRET_URL, host="mitigator.web.ctfcompetition.com")
def login():
  """Redirect the user to the SEM"""
  token = request.cookies.get('flag', 'public-demo')
  return redirect("/" + SECRET_URL + ".html?flag=" + token)

@app.route('/', host="mitigator.web.ctfcompetition.com")
def backtopwn():
  """Redirect the user to pwnable"""
  return redirect("http://mitigator.ctfcompetition.com:1337/index.html")

@app.route('/' + SECRET_URL + '.html', host="mitigator.web.ctfcompetition.com")
def sem():
  response = make_response(app.send_static_file('sem.html'))
  response.headers['content-security-policy'] = "default-src 'none'; style-src 'sha256-a6K5yWfSJ1D3n7JPrbZVrFADjNGla8XNjwqREOH1FFs='; script-src 'sha256-hJezPHmyLh3996xSSmcHvy0la57OWfPoGhLKvt40LGA=' 'sha256-9TaiPuyxl5StNVGXWFGVh2SHM62NJ9KT462mtr8Jd7Q=' https://ajax.googleapis.com/ajax/libs/jquery/3.3.1/jquery.min.js; object-src 'none'; connect-src 'self'; report-uri https://bountyplz-mitigator.web.ctfcompetition.com/";
  return response

@app.route('/secret/<path:path>', host="mitigator.web.ctfcompetition.com")
def proxy(path):
  return app.send_static_file('secret/' + path)

if __name__ == '__main__':
  app.run(host='0.0.0.0', port=8080, debug=True)

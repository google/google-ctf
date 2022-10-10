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
import json
import base64
from Crypto.PublicKey import RSA

res = requests.get('https://www.googleapis.com/oauth2/v3/certs')

keys = json.loads(res.content).get('keys')

for k in keys:
    n = k['n']
    e = k['e']
    
    n = base64.urlsafe_b64decode(n + '==')
    e = base64.urlsafe_b64decode(e + '==')
    
    pub = RSA.construct((int.from_bytes(n, 'big'), int.from_bytes(e, 'big')))
    pem = pub.exportKey()
    open(k['kid'] + '.pem', 'wb').write(pem)

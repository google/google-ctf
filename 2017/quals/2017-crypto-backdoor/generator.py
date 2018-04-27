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

# This file generates the encrypted challenge

import json
from crypto import *
from secret_data import *

# We need a smooth modulus to make DLP easy for Sage.
p = 901236131*911236121*921236161*931235651*941236273*951236179*961236149
print "p", p
g2 = 2
# Convert the generator to an equivalent point.  gy does not matter.
gy = 255466303302648575056527135374882065819706963269525464635673824
gx = ((g2 + 1)*gy) % p
g = (gx, gy)
with open('metadata.json') as f:
  data = json.load(f)
  flag = data['challenge']['flag'].strip().encode()
  print "Generating challenge for flag", flag
  A = mul(aliceSecret, g, p)
  B = mul(bobSecret, g, p)
  aliceMS = mul(aliceSecret, B, p)
  bobMS = mul(bobSecret, A, p)
  assert aliceMS == bobMS
  masterSecret = aliceMS[0]*aliceMS[1]
  length = len(flag)
  encrypted_message = encrypt(I(flag), masterSecret)
  public_data = 'attachments/public_data.py'
  crypto_backdoor = "attachments/crypto_backdoor.py"
  template = "template.py"
  crypto = "crypto.py"
  with open(template, 'r') as t, open(crypto, 'r') as cr, open(crypto_backdoor, 'w') as cb:
    lines = cr.read()
    cb.write(lines)
    cb.write("\n")
    cb.write("\n# Modulus\n")
    cb.write("p = %u\n" % p)
    cb.write("# g is the generator point.\n")
    cb.write("g = (%u, %u)\n" % g)
    cb.write("# Alice's public key A:\n")
    cb.write("A = (%u, %u)\n" % A)
    cb.write("# Bob's public key B:\n")
    cb.write("B = (%u, %u)\n" % B)
    cb.write("\n")
    lines = t.read()
    cb.write(lines)
    cb.write("# length = %u, encrypted_message = %u\n" % (length, encrypted_message))
    print "Generated", crypto_backdoor

#!/usr/bin/env python
# -*- coding: utf-8 -*-

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

from z3 import *
import re

SECRET = map(ord, '_N3x7-v3R51ON-h45-AnTI-4NTi-ant1-D3bUg_')

def Rem(a, b):
  if type(a) == int and type(b) == int:
    return a % b
  else:
    return URem(a, b)

def adler(s, a, b):
  for c in s:
    a = Rem((a + c), 65521);
    b = Rem((b + a), 65521);
  return a, b

def xor(a, b, offset=0):
  return [c ^ b[(i + offset) % len(b)] for i, c in enumerate(a)], (i + offset) % len(b)

js = u'''
function x(х) {
  ord = Function.prototype.call.bind(''.charCodeAt);
  chr = String.fromCharCode;
  str = String;
  function h(s) {
    for (i = 0; i != s.length; i++) {
      a = ((typeof a == 'undefined' ? 1 : a) + ord(str(s[i]))) % 65521;
      b = ((typeof b == 'undefined' ? 0 : b) + a) % 65521;
    }
    return chr(b >> 8) + chr(b & 0xFF) + chr(a >> 8) + chr(a & 0xFF);
  }
  function c(a, b, c) {
    for (i = 0; i != a.length; i++) c = (c || '') + chr(ord(str(a[i])) ^ ord(str(b[i%b.length])));
    return c;
  }
  for (a = 0; a != 1000; a++) debugger;
  x = h(str(x));
  source = /NEXT_STAGE/;
  source.toString = function() {
    return c(source, x);
  };
  try {
    console.log('debug', source);
    with(source) return eval('eval(c(source, x))');
  } catch(e) {}
}
'''

payload = u'''
х == c('ENCRYPTED_SECRET', h(х));
'''

def minimize(src):
  src = re.sub(
      r'(\w*)\s+',
      lambda m: m.group(0) if (m.group(1) in ['function', 'return', 'typeof', 'var']) else m.group(1),
      src,
  )
  src = re.sub(r';}', '}', src)
  src = re.sub(r';(//|$)', '//', src)
  return src

def acceptable_regexp_char(c):
  return And([c != ord(i) for i in '()[/\\'] + [c >= 0x20])

def acceptable_str_char(c):
  return And([c != ord(i) for i in '\'\\'] + [c >= 0x20])

s = Solver()
BITS = 18
DEGREE_OF_FREEDOM = 1

js = minimize(js).split(u'NEXT_STAGE')
payload = minimize(payload + ('//' if DEGREE_OF_FREEDOM > 0 else '')).split(u'ENCRYPTED_SECRET')
print js, payload

# Secret encryption
secret_adler_a = BitVec('aS', BITS)
secret_adler_b = BitVec('bS', BITS)
final_a, final_b = adler(SECRET, secret_adler_a, secret_adler_b)
s.add(BitVec('aF', BITS) == final_a, BitVec('bF', BITS) == final_b)
secret_key = [BitVec('kS%s' % i, BITS) for i in range(4)]
s.add([secret_key[0] == final_b >> 8, secret_key[1] == final_b & 0xFF, secret_key[2] == final_a >> 8, secret_key[3] == final_a & 0xFF])
secret_enc = xor(SECRET, secret_key)[0]
s.add([acceptable_str_char(c) for c in secret_enc])

# Main js prefix
a, b = adler(map(ord, js[0]), 1000, 0)
s.add(BitVec('a0', BITS) == a, BitVec('b0', BITS) == b)

# Payload
payload_key = [BitVec('k%s' % i, BITS) for i in range(4)]
s.add([And(0 < k, k < 256) for k in payload_key])
payload_enc = xor(map(ord, payload[0]) + secret_enc + map(ord, payload[1]), payload_key)[0]
s.add([acceptable_regexp_char(c) for c in payload_enc])
a, b = adler(payload_enc, a, b)
s.add(BitVec('a1', BITS) == a, BitVec('b1', BITS) == b)

# Salt for some degree of freedom
salt = [BitVec('c%s' % i, BITS) for i in range(DEGREE_OF_FREEDOM)]
s.add([And(x > 0, x < 2**16) for x in salt])
a, b = adler(salt, a, b)
s.add(BitVec('a2', BITS) == a, BitVec('b2', BITS) == b)

# Main js postfix
a, b = adler(map(ord, js[1]), a, b)

# The current checksum is the payload_key for the payload
s.add(And(payload_key[0] == b >> 8, payload_key[1] == b & 0xFF, payload_key[2] == a >> 8, payload_key[3] == a & 0xFF))
# And the starting point for the inner checksum
s.add(secret_adler_a == a, secret_adler_b == b)

print s.check()
model = s.model()
print(model)
payload_key = [model[i].as_long() for i in payload_key]
secret_key = [model[i].as_long() for i in secret_key]
salt = [model[i].as_long() for i in salt]
payload = ''.join([
    payload[0],
    ''.join(map(unichr, xor(SECRET, secret_key)[0])),
    payload[1],
])
final_js = ''.join([
    js[0],
    ''.join(map(unichr, xor(map(ord, payload), payload_key)[0])),
    ''.join(map(unichr, salt)),
    js[1],
])
print 'adler(final_js):', adler(map(ord, final_js), 1000, 0)
print repr(payload)
print repr(final_js)

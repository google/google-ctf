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
import code
import re
import sys

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

# Encrypted text
encrypted = map(ord, '\xa2\xd7&\x81\xca\xb4c\xca\xaf\xac$\xb6\xb3\xb4}\xcd\xc8\xb4T\x97\xa9\xd08\xcd\xb3\xcd|\xd4\x9c\xf7a\xc8\xd0\xdd&\x9b\xa8\xfeJ')

s = Solver()
BITS = 18

# The initial A and B when invoking the adler
a0, b0 = (2714, 33310)
secret = [BitVec('s%s' % i, BITS) for i in range(len(encrypted))]
a, b = adler(secret, a0, b0)
key = [BitVec('k%s' % i, BITS) for i in range(4)]
s.add([key[0] == b >> 8, key[1] == b & 0xFF, key[2] == a >> 8, key[3] == a & 0xFF])
result, offset = xor(secret, key)

s.add([And(r < 0x80, r >= 0x20) for r in secret])
s.add([result[i] == encrypted[i] for i in range(len(encrypted))])

print s.check()
model = s.model()
print(model)
secret = [model[i].as_long() for i in secret]
key = [model[i].as_long() for i in key]
print secret, key, adler(secret, 1, 0), xor(secret, key), encrypted
print ''.join(map(unichr, secret)),

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

import random

def KSA(key):
  keylength = len(key)
  S = range(256)
  j = 0
  for i in range(256):
    j = (j + S[i] + key[i % keylength]) % 256
    S[i], S[j] = S[j], S[i]  # swap
  return S

def PRGA(S):
  i = 0
  j = 0
  while True:
    i = (i + 1) % 256
    j = (j + S[i]) % 256
    S[i], S[j] = S[j], S[i]  # swap
    K = S[(S[i] + S[j]) % 256]
    yield K

def RC4(key):
  S = KSA(key)
  return PRGA(S)

def sig(v):
  if v & 0x80:
    return -0x100 + v
  return v

flag = 'CTF{bacon_lettuce_tomato_lobster_soul}'
key = [random.choice(range(20)) for x in range(8)]

print 'key is', key

ks = RC4(key)

print 'flag is', [sig(ord(x) ^ y) for (x, y) in zip(flag, ks)]

xor = [random.choice(range(20)) for x in range(8)]
print 'xor 1', xor
print 'xor 2', [x ^ y for (x, y) in zip(key, xor)]

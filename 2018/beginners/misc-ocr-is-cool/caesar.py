#!/usr/bin/env python2
#Copyright 2018 Google LLC
#
#Licensed under the Apache License, Version 2.0 (the "License");
#you may not use this file except in compliance with the License.
#You may obtain a copy of the License at
#
#    https://www.apache.org/licenses/LICENSE-2.0
#
#Unless required by applicable law or agreed to in writing, software
#distributed under the License is distributed on an "AS IS" BASIS,
#WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#See the License for the specific language governing permissions and
#limitations under the License.

import string

def caesar(cleartext, shift):
  ciphertext = ''
  for c in cleartext:
    if c not in string.ascii_letters:
      ciphertext += c
    else:
      if c in string.ascii_lowercase:
        start = ord('a')
      else:
        start = ord('A')
      ciphertext += chr(((ord(c) - start + shift) % 26) + start)

  return ciphertext

with open('./src.txt') as fd:
  cleartext = fd.read()

ciphertext = caesar(cleartext, 19)

with open('./enc.txt', 'w') as fd:
  fd.write(ciphertext)

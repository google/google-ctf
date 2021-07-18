#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Copyright 2020 Google LLC
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

import argparse
import base64
import json
import logging
import pwnlib
import re
import socket
import sys

from Cryptodome.Cipher import AES

AES_KEY = b'eaW~IFhnvlIoneLl'


def trim_padding(byte_array):
  padding_len = byte_array[-1]
  if padding_len < 16:
    return byte_array[:-padding_len]
  return byte_array


def add_padding(byte_array):
  if len(byte_array) % 16 == 0:
    return byte_array
  padding_len = 16 - len(byte_array) % 16
  logging.debug('padding_len = %d' % padding_len)
  return byte_array + bytes([padding_len] * padding_len)


def handle_pow(r):
  print(r.recvuntil(b'python3 '))
  print(r.recvuntil(b' solve '))
  challenge = r.recvline().decode('ascii').strip()
  p = pwnlib.tubes.process.process(['kctf_bypass_pow', challenge])
  solution = p.readall().strip()
  r.sendline(solution)
  print(r.recvuntil(b'Correct\n'))


if __name__ == '__main__':
  parser = argparse.ArgumentParser(
      description='gCTF-2021 rev-adspam healthcheck.')
  parser.add_argument('--host', type=str, help='Connection host (default is 127.0.0.1).')
  parser.add_argument('--port', type=int, help='Connection port (default is 1337).')
  parser.add_argument('--license', type=str, help='License path.')
  parser.add_argument('--nopow', action='store_true', help='Disabes proof-of-work.')

  args = parser.parse_args()

  host = '127.0.0.1' if not args.host else args.host
  port = 1337 if not args.port else args.port
  license_path = '/home/user/lic' if not args.license else args.license

  r = pwnlib.tubes.remote.remote(host, port)

  if not args.nopow:
    print(r.recvuntil('== proof-of-work: '))
    if r.recvline().startswith(b'enabled'):
      handle_pow(r)

  words = open(license_path, 'r').read().split('\n')

  # Break the deserialization
  words[-1] = words[8]
  words.append(words[8])
  words.append(words[8])
  words.append(words[8])
  words.append(words[8])
  words.append(words[8])
  words.append(words[8])
  words.append(words[8])
  words.append(words[8])
  words.append(words[8])
  words.append(words[8])
  words.append(words[8])
  words.append(words[8])


  cipher = AES.new(AES_KEY, AES.MODE_ECB)
  packet = {'name': '1337_hacker', 'license': '::'.join(words)}

  data = base64.b64encode(
      cipher.encrypt(add_padding(json.dumps(packet).encode('utf-8'))))

  r.sendline(data)
  response = r.recvline(4096)
  print(trim_padding(cipher.decrypt(base64.b64decode(response))))
  r.close()

exit(0)

#!/usr/bin/env python3
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

import sys
import random

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend


def ReadPrivateKey(filename):
  return serialization.load_pem_private_key(
      open(filename, 'rb').read(), password=None, backend=default_backend())


def RsaDecrypt(private_key, ciphertext):
  assert (len(ciphertext) <=
          (private_key.public_key().key_size // 8)), 'Ciphertext too large'
  return pow(
      int.from_bytes(ciphertext, 'big'),
      private_key.private_numbers().d,
      private_key.public_key().public_numbers().n)


def Challenge(private_key, reader, writer):
  try:
    m0 = reader.read(1)
    m1 = reader.read(1)
    ciphertext = reader.read(private_key.public_key().key_size // 8)
    dice = RsaDecrypt(private_key, ciphertext)
    for rounds in range(100):
      p = [m0, m1][dice & 1]
      k = random.randint(0, 2)
      c = (ord(p) + k) % 2
      writer.write(bytes((c,)))
    writer.flush()
    return 0

  except Exception as e:
    return 1


def main():
  private_key = ReadPrivateKey(sys.argv[1])
  return Challenge(private_key, sys.stdin.buffer, sys.stdout.buffer)


if __name__ == '__main__':
  sys.exit(main())

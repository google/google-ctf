# Copyright 2023 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""A brute-force attempt at cracking the password.

It only uses the fact that the password was generated from a given dictionary.

It should not be able to find the password in a reasonable time. It does crack
the passwords consisting of 2 words quickly, though.
"""

import itertools
import pyrage
from pyrage import passphrase
import re


def get_word_list():
  with open('USACONST.TXT', encoding='ISO8859') as f:
    text = f.read()
  return list(set(re.sub('[^a-z]', ' ', text.lower()).split()))


def generate_passwords():
  words = get_word_list()
  for length in range(1, len(words)+1):
    for combination in itertools.combinations(words, length):
      for password in itertools.permutations(combination):
        yield ''.join(password)


def decrypt(cyphertext):
  for i, password in enumerate(generate_passwords()):
    try:
      print(f'Trying {i}th password: {password}')
      content = passphrase.decrypt(cyphertext, password)
      print(f'\nThe password was {password}')
      return content
    except (RuntimeError, pyrage.DecryptError):
      continue

if __name__ == '__main__':
  secret = decrypt(open('secret.age', 'rb').read())
  print(f'The secret is: {secret.decode("utf-8")}')

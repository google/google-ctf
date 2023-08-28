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

"""A less brute-force attempt at cracking the password.

It uses the fact that the password was generated from a given dictionary and it
also looks at the hint to get the number of occurrences of each letter.

It should not be able to find the password in a reasonable time.
"""

import itertools
import pyrage
from pyrage import passphrase
import re


def get_word_list():
  with open('USACONST.TXT', encoding='ISO8859') as f:
    text = f.read()
  return list(set(re.sub('[^a-z]', ' ', text.lower()).split()))


def get_signature(text):
  signature = [0] * 26
  for c in text:
    signature[ord(c)-ord('a')] += 1
  return tuple(signature)


def get_signature_from_hint():
  with open('hint.dot') as f:
    return get_signature([
        match.group(1)
        for line in f.readlines()
        if (match := re.search('label=([a-z])', line))
    ])


def promising_signature(signature, target_signature):
  for s, t in zip(signature, target_signature):
    if s > t:
      return False
  return sum(signature) <= sum(target_signature)


def combinations(words, target_signature):
  words = sorted(words, key=len, reverse=True)
  attempts = [((), get_signature(''))]
  while attempts:
    attempt, signature = attempts.pop(0)
    if signature == target_signature:
      yield attempt
    if not promising_signature(signature, target_signature):
      continue
    for word in words:
      new_attempt = attempt + (word,)
      new_signature = get_signature(''.join(new_attempt))
      if promising_signature(new_signature, target_signature):
        attempts.append((new_attempt, new_signature))


def generate_passwords():
  words = get_word_list()
  signature = get_signature_from_hint()
  for combination in combinations(words, signature):
    print(f'Checking {combination}')
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

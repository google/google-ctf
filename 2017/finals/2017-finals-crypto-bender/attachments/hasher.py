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

import sys
import hashlib

P = 81850485515597750841436942709970209097401568904524680443650925844955456713411
BLOCK_LEN = 28

def I(s):
  """Convert a binary string to an int."""
  val = 0
  for i in range(len(s)):
    digit = ord(s[len(s) - i - 1])
    val <<= 8
    val |= digit
  return val

def Sn(i, length):
  """Convert an int to a binary string."""
  s = ''
  while i != 0:
    digit = i & 0xff
    i >>= 8
    s += chr(digit)
  if len(s) > length:
    raise Exception("Integer too big to fit")
  while len(s) < length:
    s += chr(0)
  return s

def findDigest(text):
  textLen = len(text);
  # Allow up to 16 MiB file sizes.
  if textLen > 1 << 24:
    raise Exception("Input text too big!")
  # Pad with 0's.
  while len(text) % BLOCK_LEN != 0:
    text += b"\0"
  numBlocks = len(text) // BLOCK_LEN
  digest = textLen
  for i in range(numBlocks):
    block = text[i*BLOCK_LEN:(i+1)*BLOCK_LEN] + Sn(i, 4)
    digest += I(hashlib.sha256(block).digest())
  return digest % P

if __name__ == "__main__":

  fileName = sys.argv[1]
  with open(fileName, 'rb') as will:
    text = will.read()
    digest = findDigest(text)
    print("Digest: %064x" % digest)

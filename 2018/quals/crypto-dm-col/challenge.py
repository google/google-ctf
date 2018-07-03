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

import logging
import sys
import collections

from not_des import *

Block = collections.namedtuple('Block', ['key', 'input', 'output'])

logger = logging.getLogger('challenge')


def ReadFlag(filename):
  return open(filename, 'rb').read()


def Compress(reader):
  """Davies–Meyer single-block-length compression function."""
  key = reader.read(KEY_SIZE)
  inp = reader.read(BLOCK_SIZE)
  output = Xor(DESEncrypt(inp, key), inp)
  return Block(key, inp, output)


def Challenge(flag, reader, writer):
  try:
    b1 = Compress(reader)
    b2 = Compress(reader)
    b3 = Compress(reader)

    if b1.key + b1.input == b2.key + b2.input:
      writer.write(b'Input blocks should be different.')
      writer.flush()
      return 1

    if b1.output != b2.output:
      writer.write(b'No collision detected.')
      writer.flush()
      return 1

    if b3.output != [0] * BLOCK_SIZE:
      writer.write(b'0 pre-image not found.')
      writer.flush()
      return 1

    writer.write(flag)
    writer.flush()
    return 0

  except Exception as e:
    return 1


def main():
  logging.basicConfig(stream=sys.stderr, level=logging.DEBUG)
  flag = ReadFlag(sys.argv[1])
  return Challenge(flag, sys.stdin.buffer, sys.stdout.buffer)


if __name__ == '__main__':
  sys.exit(main())

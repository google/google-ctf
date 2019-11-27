#!/usr/bin/python
# Copyright 2018 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http:#www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
import random
import sys

FLAG = "flag{MixingOfGoldenBits}"
if len(FLAG) >= 31:
  sys.exit("flag too long")

bits = list(range(256))
random.shuffle(bits)

flips = [random.randint(0, 1) for x in range(256)]

flag = FLAG.ljust(32, '\0')
flag = bytearray(flag)

output = bytearray(32)

for i in range(256):
  bit = bits[i] % 8
  byte = bits[i] / 8
  b = (flag[byte] >> bit) & 1
  if flips[i]:
    b ^= 1

  bit = i % 8
  byte = i / 8
  output[byte] |= b << bit


with open("mixer.c", "w") as f:
  f.write("uint8_t mix_bits[] = { ")
  f.write(','.join(["%u" % x for x in bits]))
  f.write(" };\n")

  f.write("uint8_t mix_flips[] = { ")
  f.write(','.join(["%u" % x for x in flips]))
  f.write(" };\n")

  f.write("uint8_t flag[] = { ")
  f.write(','.join(["%u" % x for x in output]))
  f.write(" };\n")


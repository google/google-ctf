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

__author__      = "Ian Eldred Pudney"

import sys
import random
import textwrap
lines = sys.stdin.readlines()
hexes = " ".join(lines).strip().split(" ")
bytes = [int(x, 16) for x in hexes]

random.seed(a=sum(bytes))

sum_buffer = [random.randint(0, 255) for b in bytes]

ciphertext = [0]*len(bytes)
for i in range(0, len(bytes)):
  ciphertext[i] = (bytes[i] + sum_buffer[i]) % 256

for i in range(0, len(ciphertext)):
  while ciphertext[i] == 0 or sum_buffer[i] == 0:
    sum_buffer[i] = (sum_buffer[i] + 255) % 256
    ciphertext[i] = (bytes[i] + sum_buffer[i]) % 256


blocks = [[]]
index = 0

for c in ciphertext:
  blocks[-1].append(c)
  index += 1
  if (index == 64):
    index = 0
    blocks.append([])

sum_blocks = [[]]
index = 0

for c in sum_buffer:
  sum_blocks[-1].append(c)
  index += 1
  if (index == 64):
    index = 0
    sum_blocks.append([])


#__attribute__((section(\".text\")))
print "#include \"xorstr.h\""
print "#include \"string.h\""
print "static constexpr unsigned long long enc_" + sys.argv[1] + "_size = " + str(len(ciphertext)) + "L;"

print "static char* enc_" + sys.argv[1] + " =[]()->char* {"
for i in range(0, len(blocks)):
  print "  auto xs" + str(i) + " = xorstr(\"\\x" + "\\x".join([format(c, 'x') for c in blocks[i]]) + "\\xff\");"
  print "  auto xsp" + str(i) + " = xorstr(\"\\x" + "\\x".join([format(c, 'x') for c in sum_blocks[i]]) + "\\xff\");"

print "  static char data[enc_" + sys.argv[1] + "_size * 2];"

for i in range(0, len(blocks) - 1):
  print "  memcpy(data + (" + str(64*i) + "), xs" + str(i) + ".crypt_get(), 64);"
print "  memcpy(data + (" + str(64*(len(blocks)-1)) + "), xs" + str(len(blocks)-1) + ".crypt_get(), " + str(len(ciphertext) - 64*(len(blocks)-1)) + ");"

for i in range(0, len(sum_blocks) - 1):
  print "  memcpy(data + enc_" + sys.argv[1] + "_size + (" + str(64*i) + "), xsp" + str(i) + ".crypt_get(), 64);"
print "  memcpy(data + enc_" + sys.argv[1] + "_size + (" + str(64*(len(sum_blocks)-1)) + "), xsp" + str(len(sum_blocks)-1) + ".crypt_get(), " + str(len(ciphertext) - 64*(len(sum_blocks)-1)) + ");"

print "  return data;\n}();"


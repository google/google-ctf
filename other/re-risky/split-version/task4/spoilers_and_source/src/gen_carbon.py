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

FLAG = 'flag{PrettyRiskvChallenge}'

funcs = ""
checks = ""

tags = set()

FLAG += '\0'

def get_tag():
  while True:
    tag = random.randint(0x100000, 0xffffff)
    if tag not in tags:
      break
  tags.add(tag)
  return "%.6x" % tag

for i, ch in enumerate(FLAG):
  tag = get_tag()
  xor_byte = random.randint(0x00, 0xff)

  funcs += "bool check_%s(uint8_t ch) { return (ch ^ 0x%.2x) == 0x%.2x; }\n" % (
    tag, xor_byte, ord(ch) ^ xor_byte
  )

  checks += "  if (check_%s(flag[%i]))\n" % (tag, i)

checks += '    { puts("Well done!"); return 0; }\n  return 1;';

d = open("carbon.c.template").read()

d = d.replace('/*FUNCTIONS_TEMPLATE*/', funcs)
d = d.replace('/*CALLS_TEMPLATE*/', checks)

out = d
f = open("carbon.c", "w")
f.write(out)
f.close()



# Copyright 2022 Google LLC
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

import dis
import types
import marshal
import sys

import solution_dis


def some_normal_function(x):
  arr = []
  for i in range(5):
    arr.append(i)
    print(i)
  a = 1
  return x + 2

def another():
  x = 1
  print("This", "is", "a", x, "long", "call")

def do_fun(f):
  print(solution_dis._format_code_info(f))
  print(repr(f._co_code_adaptive))
  solution_dis.dis(f, adaptive=True)

with open(sys.argv[1], 'rb') as f:
  f.seek(16)
  lf = marshal.load(f)
  #print(repr(some_normal_function.__code__.co_code))
  dis.dis(some_normal_function)
  #print("---")
  #print(repr(another.__code__.co_code))
  #dis.dis(another)
  #print(lf)
  #print(dir(lf))
  #print(lf.co_code)
  #print(lf.co_consts)
  #print(dis._format_code_info(lf))
  for const in lf.co_consts:
    if isinstance(const, types.CodeType):
      print("---")
      do_fun(const)

m = 1267034045110727999721745963007
for i in range(10):
  s = ""
  for j in range(10):
    s += "#" if (m >> (i*10+j)) & 1 else " "
  print(s)

s = "seed:"
#s += "sssddwwddwddsssdssaawwssaaaassddddddd"
s += "sssddwwddwddsssdssaaawwssaaaassddddddd"
s += ":_17_31_72_3_2_:"
text = "Because of its performance advantage, today many language implementations\n  execute a program in two phases, first compiling the source code into bytecode,\n  and then passing the bytecode to the virtual machine."
s += "_" + "_".join(word.upper() for word in text.split()) + "_"
print(s)

crypted = b'\xa0?n\xa5\x7f)\x1f6Jvh\x95\xcc!\x1e\x95\x996a\x11\xf6OV\x88\xc1\x9f\xde\xb50\x9d\xae\x14\xde\x18YHI\xd8\xd5\x90\x8a\x181l\xb0\x16^O;]'

flag = ""
import random
random.seed(s)
for i in range(len(crypted)):
  r = random.randint(0, 255)
  r *= 13
  r += 17
  r %= 256
  r ^= crypted[i]
  flag += chr(r)

print(repr(flag))
# Flag algo:


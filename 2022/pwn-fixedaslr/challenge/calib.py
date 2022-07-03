#!/usr/bin/python3
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
#
#
# This is just a script I used to manually calibrate the PRNG.
from z3 import *
import sys

BITS = 12
N = BITS * 6
rand_state = 0x1234567890abcdef

def get_bit(v, n):
  return (v >> n) & 1

def get_bit_z3(v, n):
  return Extract(n, n, v)

def rand():
  global rand_state
  BIAS = 63 - 16

  new_bit = (
      1 ^
      get_bit(rand_state, BIAS + 16) ^
      get_bit(rand_state, BIAS + 14) ^
      get_bit(rand_state, BIAS + 13) ^
      get_bit(rand_state, BIAS + 11)
  )

  rand_state = ((rand_state << 1) & 0xffffffffffffffff) | new_bit
  return new_bit

def check_period():
  org_state = rand_state
  cnt = 0
  while 1:
    rand()
    cnt += 1
    if org_state == rand_state:
      break

    if cnt & 0xfffff == 0:
      print(f"{rand_state:016X}", end="\r")
      #sys.stdout.write('.')
      sys.stdout.flush()

  return cnt

#print(check_period())

n = []
for i in range(N):
  r = rand()
  #print(i, r)
  n.append(r)

print("---- solving")
rs = BitVec("rs", 64)
recovered_state = rs
n_step = []
for _ in range(N):
  BIAS = 63 - 16
  new_bit = (
      1 ^
      get_bit_z3(recovered_state, BIAS + 16) ^
      get_bit_z3(recovered_state, BIAS + 14) ^
      get_bit_z3(recovered_state, BIAS + 13) ^
      get_bit_z3(recovered_state, BIAS + 11)
  )

  recovered_state = Concat(Extract(62, 0, recovered_state), new_bit)
  n_step.append(new_bit)

s = Solver()
for i in range(N):
  s.add(n_step[i] == n[i])

while s.check().r == 1:
  m = s.model()
  print(hex(m[rs].as_long()))
  s.add(rs != m[rs].as_long())



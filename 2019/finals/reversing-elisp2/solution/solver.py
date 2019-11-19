# Copyright 2019 Google LLC

# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at

#     https://www.apache.org/licenses/LICENSE-2.0

# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from random import shuffle

check_against = [24, 28, 27, 29, 10, 16, 6, 7, 4, 21, 4, 23, 11, 10, 16, 8, 14, 29, 3, 21, 16, 19, 2, 3, 23, 12, 20, 6, 3, 30, 12, 15, 23, 11, 29, 12, 18, 9, 25, 4, 17, 19, 23, 1, 28, 12, 30, 11, 27, 14, 16, 6, 19, 0, 26, 1, 31, 15, 11, 12, 7]
flag_parts = "..n..0.._..D..1..y..R..D..o..4.._..1..y..r..o.._W.i.._.._.u.5"

xor_value = 0b10110
x0 = 0b11001
x1 = 0b10101
x2 = 0b00100
x3 = 0b11000
x4 = 0b11100
x5 = 0b00110
x6 = 0b00111
x7 = 0b10010

flag = "*"*len(check_against)

i = 0

j = 0

def valid_char(char, place):
  global check_against
  if flag_parts[place] != '.' and char != flag_parts[place]:
    return False

  o = ord(char)
  if not ((o >= ord('a') and o <= ord('z'))
     or (o >= ord('A') and o <= ord('Z'))
     or (o >= ord('0') and o <= ord('9'))
     or o == ord('_')):
    return False

  return True

def recurse():
  global check_against
  global flag
  global i
  global j
  global x0
  global x1
  global x2
  global x3
  global x4
  global x5
  global x6
  global x7
  global xor_value

  j += 1
  if (j >= 10000):
    exit(0)

  # print(flag)

  if i >= len(check_against):
    return True

  flag_check_bits = xor_value ^ check_against[i]
  # Traverse the paths in a random order to make sure that there's only one
  # solution no matter how the competitor implements the traversing algo.
  rng = range(8)
  shuffle(rng)
  for flag_permute_bits in rng:
    prev_stuff = (xor_value, x0, x1, x2, x3, x4, x5, x6, x7)

    if flag_permute_bits == 0:
      xor_value ^= x0
    elif flag_permute_bits == 1:
      xor_value ^= x1
    elif flag_permute_bits == 2:
      xor_value ^= x2
    elif flag_permute_bits == 3:
      xor_value ^= x3
    elif flag_permute_bits == 4:
      xor_value ^= x4
    elif flag_permute_bits == 5:
      xor_value ^= x5
    elif flag_permute_bits == 6:
      xor_value ^= x6
    elif flag_permute_bits == 7:
      xor_value ^= x7

    x0 ^= flag_permute_bits
    x1 ^= flag_permute_bits
    x2 ^= flag_permute_bits
    x3 ^= flag_permute_bits
    x4 ^= flag_permute_bits
    x5 ^= flag_permute_bits
    x6 ^= flag_permute_bits
    x7 ^= flag_permute_bits

    flag = flag[:i] + chr((flag_check_bits << 3) | flag_permute_bits) + flag[i+1:]
    if valid_char(flag[i], i):
      i += 1

      if recurse():
        return True

      i -= 1
    flag = flag[:i] + '*' + flag[i+1:]

    xor_value, x0, x1, x2, x3, x4, x5, x6, x7 = prev_stuff

  return False

correct_flag = "run_y0ur_C0De_1N_y0UR_eD1ToR_4nD_3d1t_y0Ur_Cod3_WHil3_1T_run5"

# Sanity-check: Even with 1000 different random traversals, we should only ever
# deduce the correct flag.
for k in range(1000):
  prev_stuff = (xor_value, x0, x1, x2, x3, x4, x5, x6, x7, flag, i, j)
  if not recurse():
    print("Flag not founc :C")
    exit(1)
  if flag != correct_flag:
    print("Found a fake flag :C")
    print(flag)
    print(j)
  if k == 999:
    print(flag)
  xor_value, x0, x1, x2, x3, x4, x5, x6, x7, flag, i, j = prev_stuff

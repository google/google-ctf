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

# The checker from chall.el, re-implemented in Python.

flag_parts =   "..n..0.._..D..1..y..R..D..o..4.._..1..y..r..o.._W.i.._.._.u.5"
check_against = [24, 28, 27, 29, 10, 16, 6, 7, 4, 21, 4, 23, 11, 10, 16, 8, 14, 29, 3, 21, 16, 19, 2, 3, 23, 12, 20, 6, 3, 30, 12, 15, 23, 11, 29, 12, 18, 9, 25, 4, 17, 19, 23, 1, 28, 12, 30, 11, 27, 14, 16, 6, 19, 0, 26, 1, 31, 15, 11, 12, 7]

def check(flag):
  global check_against
  # The xor literals that get rewritten in the elisp file while the
  # code is running
  xor_value = 0b10110
  x0 = 0b11001
  x1 = 0b10101
  x2 = 0b00100
  x3 = 0b11000
  x4 = 0b11100
  x5 = 0b00110
  x6 = 0b00111
  x7 = 0b10010

  for i in range(len(flag)):
    f = ord(flag[i])
    flag_check_bits = f >> 3
    flag_permute_bits = f & 0b111

    if flag_check_bits ^ xor_value != check_against[i]:
      return False

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

  for c in flag:
    if flag_parts[i] != '.' and flag_parts[i] != flag[i]:
      return False

    o = ord(c)
    if not ((o >= ord('a') and o <= ord('z'))
       or (o >= ord('A') and o <= ord('Z'))
       or (o >= ord('0') and o <= ord('9'))
       or o == ord('_')):
      return False

  return True

# Sanity check: We should not return true if we modify a single character in the flag.
correct_flag = "run_y0ur_C0De_1N_y0UR_eD1ToR_4nD_3d1t_y0Ur_Cod3_WHil3_1T_run5"
print("checking incorrect flags")
for i in range(len(correct_flag)):
  for o in range(ord('0'), ord('z')):
    c = chr(o)
    if c == correct_flag[i]:
      continue
    flag_try = correct_flag[:i] + c + correct_flag[i+1:]
    if check(flag_try) == True:
      print("Passed on an incorrect flag :C " + flag_try)
      ccb = ord(correct_flag[i]) & 0b1111
      cpb = ord(correct_flag[i]) >> 4
      tcb = ord(c) & 0b1111
      tpb = ord(c) >> 4
      print("check bits: " + bin(ccb)[2:] + " -> " + bin(tcb)[2:])
      print("permute bits: " + bin(cpb)[2:] + " -> " + bin(tpb)[2:])
      print("permute bits: %d -> %d" % (cpb, tpb))
print("none returned true")

print("checking " + correct_flag)
print(check(correct_flag))

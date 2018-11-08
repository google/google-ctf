# Copyright 2018 Google LLC
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

# The python equivalent of the checker code in code.txt

perm1 = [4, 52, 58, 5, 41, 49, 25, 12, 11, 66, 24, 86, 44, 19, 77, 54, 56, 8, 60, 84, 23, 73, 89, 46, 15, 63, 9, 71, 16, 2, 7, 74, 53, 48, 14, 64, 87, 57, 90, 65, 69, 28, 43, 40, 42, 72, 27, 67, 33, 55, 29, 59, 34, 0, 1, 78, 22, 88, 81, 17, 85, 18, 3, 61, 36, 31, 26, 37, 82, 6, 80, 62, 13, 35, 68, 21, 70, 47, 83, 75, 79, 10, 32, 39, 76, 51, 45, 50, 20, 30, 38]
perm2 = [81, 1, 41, 77, 4, 29, 57, 31, 30, 21, 0, 38, 9, 83, 75, 28, 73, 62, 50, 5, 39, 60, 85, 58, 24, 64, 17, 65, 19, 80, 40, 52, 43, 8, 68, 47, 72, 66, 37, 55, 46, 12, 3, 79, 26, 32, 59, 53, 25, 18, 2, 69, 82, 6, 86, 61, 76, 22, 45, 48, 90, 67, 27, 15, 84, 35, 14, 16, 70, 10, 74, 7, 88, 87, 51, 44, 34, 13, 78, 89, 71, 11, 23, 20, 49, 63, 56, 33, 36, 54, 42]
consts = [0x1c, 0xb7, 0x30, 0x74, 0x5d, 0x3d, 0x6e, 0x4d, 0x37, 0x6b, 0x73, 0xf4, 0x34, 0xdb, 0x1c, 0x5e, 0x09, 0xc0, 0x8a, 0x2b, 0x33, 0xeb, 0x78, 0xcd, 0x6c, 0x8b, 0x52, 0x13, 0x70, 0x3f, 0x12, 0xf7, 0x33, 0xe1, 0xb4, 0x8e, 0x1c, 0x40, 0x49, 0xc4, 0x2c, 0x3b, 0x58, 0x48, 0x7a, 0x74, 0xee, 0x48, 0xeb, 0x9f, 0x00, 0x13, 0x0b, 0x3c, 0x33, 0x5c, 0xf0, 0x27, 0x69, 0x6b, 0xbc, 0x48, 0xda, 0xb4, 0x67, 0xd6, 0x0a, 0x4c, 0x5f, 0x4f, 0x5f, 0x44, 0x53, 0xc5, 0x5f, 0x74, 0xb4, 0xb7, 0x15, 0xdb, 0x5f, 0xca, 0xed, 0xe0, 0x11, 0xd8, 0x16, 0xcd, 0x34, 0xf0, 0x5f]


def check(flag):
  mix = [-1]*len(flag)
  for i in range(len(perm1)):
    newpos = perm1[i]
    c = ord(flag[i])

    type = 2*(newpos%2) + i%2
    if type == 0:
      c = c ^ 0x42
    elif type == 1:
      c = (c + 123) % 256
    elif type == 2:
      c = (~c) % 256
    else:
      c = (c >> 4) | ((c & 0x0f) << 4)

    mix[newpos] = c

  print(mix)

  for i in range(len(mix)):
    newpos = perm2[i]
    c = mix[i]

    type = 2*(newpos%2) + i%2
    if type == 0:
      c = (c + 0x42) % 256
    elif type == 1:
      c = (~c) % 256
    elif type == 2:
      c = (c >> 6) | ((c & 0x3f) << 2)
    else:
      c = c ^ 123

    if c != consts[newpos]:
      return False

  return True

flag = "Y0_D4Wg_I_h3Rd_Y0U_lik3_pRoc3SsIng_TexT_sO_1_wRo73_A_73Xt_pR0C3sSOr_1NSId3_4_t3Xt_Pr0C3ssoR"

# Sanity check: The flag shouldn't be correct if any char is replaced with any other char.
for i in range(len(flag)):
  for c in range(256):
    if c == ord(flag[i]):
        continue
    flag2 = flag[:i] + chr(c) + flag[i+1:]
    if check(flag2):
      print "Also correct:"
      print flag2
      exit(1)

print check(flag)

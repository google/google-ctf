#!/usr/bin/python
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

flag = "CTF[LINKED-LISTS-AND-40-BIT-FLOATS]"

# linked-lists-and-40-bit-floats
# linked-lists-and-40-bit-floatr
# kinked-lists-and-40-bit-floats
# what might be the password ???


tested_flag = flag[4:-1]
print tested_flag

#>>> hex(int("00101010101010101010101010101011",2)<<1)
#'0x55555556'

#base_ma = int("00101010101010101010101010101011",2)<<1

def get_bit(s, bit):
  s = bytearray(s)
  i_byte = bit / 8
  i_bit = bit % 8
  return (s[i_byte] >> i_bit) & 1

vs = 0
limit = len(tested_flag) * 8
#                 0        1         2         3
#                 12345678901234567890123456789012
#                    . . . . . . . . . . . . .
#                 00101110101110111011101010111100
#                 00101110101110111011101010111011
base = bytearray("00101010101010101010101010101010")
k = base[:]
fakes = "0011"
ln = 1
for i in xrange(limit):
  k[3 + vs * 2] = str(get_bit(tested_flag, i))
  vs += 1

  if vs == 13 or i == limit - 1:
    s = str(k)
    v = hex(int(s, 2) << 1)[2:]
    hh = hex(int(s, 2))[2:]
    print hh[0:2], hh[2:4], hh[4:6], hh[6:],  # C64 representation
    f = float.fromhex('0x1.%s%sp-1' % (v, fakes))
    print "  %i %c = %.15f" % (ln * 10, chr(0x60 + ln), f)
    ln += 1
    k = base[:]
    vs = 0



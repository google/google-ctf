# Copyright 2024 Google LLC
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

from pwn import *
import sys

elf = ELF(sys.argv[1])
sec_bytes = elf.section("encrypted")
sec = elf.get_section_by_name("encrypted")

open("/tmp/orig_section", "wb").write(b'\x00' * 0x2000 + sec_bytes)

off = sec.header.sh_offset

real_perm = [222, 182, 104, 196, 208, 215, 152, 142, 21, 176, 158, 117, 219, 15, 113, 251, 133, 124, 47, 45, 96, 255, 242, 190, 98, 43, 161, 149, 153, 209, 91, 13, 165, 199, 58, 53, 214, 48, 64, 18, 228, 73, 61, 246, 107, 201, 108, 178, 8, 71, 26, 105, 52, 36, 83, 88, 54, 131, 240, 187, 197, 204, 32, 3, 162, 76, 202, 227, 128, 2, 211, 231, 66, 23, 17, 248, 229, 12, 186, 50, 220, 27, 112, 233, 192, 221, 217, 170, 141, 134, 213, 40, 85, 177, 84, 163, 33, 25, 132, 75, 239, 140, 212, 174, 157, 39, 123, 106, 42, 44, 22, 31, 146, 65, 164, 102, 19, 223, 173, 238, 236, 147, 115, 94, 156, 138, 160, 185, 56, 89, 62, 57, 7, 95, 184, 241, 210, 126, 232, 87, 169, 74, 130, 68, 5, 188, 92, 168, 237, 172, 4, 67, 60, 191, 99, 139, 203, 167, 20, 72, 119, 125, 63, 116, 226, 118, 247, 207, 175, 250, 159, 148, 120, 103, 16, 235, 6, 195, 49, 218, 253, 80, 14, 225, 154, 59, 46, 86, 69, 38, 166, 249, 244, 194, 234, 82, 245, 110, 129, 206, 41, 198, 151, 111, 93, 37, 55, 51, 143, 78, 79, 97, 144, 252, 81, 9, 136, 155, 90, 145, 122, 137, 34, 135, 24, 1, 10, 109, 70, 205, 171, 121, 30, 29, 179, 100, 254, 127, 243, 11, 150, 200, 181, 189, 101, 180, 193, 216, 77, 114, 230, 183, 28, 224, 0, 35]

perm = {
    0x5c: 0x55,
    0x9f: 0x48,
    0xdd: 0x89,
    0x4c: 0xe5,
    0xcc: 0x5d, # pop rbp
    0xb1: 0xc3,
    0x15: 0xff,
    0xfe: 0x00,

    # These are the few bytes repeating consecutively in <game>
    #0xa0: 0x90,
    #0xa5: 0x90,
    #0x3e: 0x90, # known below
    #0xe3: 0x90,
    #0xf9: 0x90,

    # These are the bytes that seem to be 8*i
    0x3a: 0xf0,
    0x4b: 0xf8,
    #0xfe: 0x00 # We already know this one
    0x30: 0x08,
    0xae: 0x10,
    0xe0: 0x18,
    0x3e: 0x20,
    0x5b: 0x28,
    0x25: 0x30,
    0x80: 0x38,
    0x26: 0x40,
    #0x9f: 0x48, # We already know this one
    0xb5: 0x50,
    0x37: 0x58,
    0x14: 0x60,
    0x02: 0x68,
    0x52: 0x70,
    0xac: 0x78,
    0x44: 0x80,
    0xd8: 0x88,
    0xd4: 0x90,
    0x06: 0x98,
    0x7e: 0xa0,
    0x93: 0xa8,
    0x09: 0xb0,
    # We also know this from "movabs rax, imm64" - 48 b8 imm64
    0x86: 0xb8,
    0x54: 0xc0,
    0xf1: 0xc8,
    0x04: 0xd0, # this and the next is wrong???
    0xf7: 0xd8,

    # We know these from the movabs ra/dx, imm64; mov [rbp-X], ra/dx pattern
    #0x4e: 0xba, not sure
    0x10: 0x85, # changed from 45
    #0x1b: 0x55, not sure


    # prolog of <game>
    0xc6: 0x81,
    0x78: 0xec,
    0xf3: 0xbd,

# snippet 1
    0x4e: 0xba,
    0x1b: 0x95, # Changed from 55
    0xbc: 0x45,

    0xf2: 0xb5,

# missing 8n:
#    0xc7: 0xe0, # maybe it's d0/d8 instead??? 2117
#    0x24: 0xe8,

# rsi/rdi
    0x17: 0xbe,
    0x99: 0xbf,

    0xec: 0xfe, # 3dfa

    # 3f11
    0x0b: 0x75,
    0xa1: 0x7d,

    # <back>
    0x58: 0x8d,
    0x39: 0x83,

    # call!
    0x8a: 0xe8,

    0x21: 0xc7, # mov rdi, rax

    # printf offsets and other call offsets
    0x94: 0xed,
    0xa8: 0xaf,
    0x3c: 0xc5,
    0x38: 0x36,
    0xc9: 0xc6,
    0xb3: 0xda,
    0xf6: 0xc1,
    0xbb: 0x56,
    0x72: 0xa4,
    0x2d: 0xc9,
    0x76: 0xad,
    0xa6: 0xf7,
    0x0c: 0xdb,
    0xfd: 0xe0,
    0x9c: 0xcb,
    0xe5: 0xcd,
    0xa7: 0xcf,
    0x88: 0xd2,
    0x70: 0x92,
    0x66: 0xd4,
    0xe7: 0x79,
    0x5a: 0xd5,
    0x9a: 0x63,
    0x96: 0x04,
    0xee: 0xf3,
    0x05: 0xd7,
    0xab: 0x94,
    0x56: 0xd9,
    0xf5: 0xb4,
    0xe9: 0x1d,
    0xb0: 0x06,
    0x8e: 0x82,
    0x1a: 0xa1,
    0xc7: 0xce,
    0x61: 0x19, #looks wrong, should be ascii
    0xe4: 0x46,
    0x7a: 0x73,
    0x55: 0xdd,
    0x0a: 0x9e,
    0xc2: 0xea,
    0x00: 0xde,
    0xa9: 0xfa,
    0x75: 0xdf,
    0xd2: 0x4f,
    0xa4: 0xe2,
    0x43: 0xe3,
    0x28: 0xe4,
    0x32: 0x1a,
    0x59: 0x86,
    0xfc: 0x1c,
    0xfa: 0xe6,
    0x71: 0x41,
    0x47: 0xe7,
    0xa2: 0x3f,
    0x53: 0xe9,
    0x45: 0x02,
    0xaf: 0xeb,
    0x64: 0xef,
    0x77: 0xee,
    0x6f: 0x1f,
    0x31: 0x47,
    0xcb: 0x6f,
    0x49: 0x17,


    0x24: 0xd6, # mov rsi, rdx
    0xb4: 0xfd,

    # ascii
    0xf9: ord('r'),
    0xa3: ord('t'),
    0xc5: ord('n'),
    0x33: ord('i'),

    0x8f: ord('D'),
    0x69: ord("'"),
    0xf4: ord('e'),
    0xd3: ord('a'),

    0x81: ord('Y'),
    0xa5: ord('v'),
    0x6d: ord(','),
    0x2e: ord('l'),
    0x2c: ord('k'),
    0xeb: ord('d'),
    0x73: ord('f'),
    0xad: ord('g'),

    0x29: ord('I'),
    0xe3: ord('m'),
    0xa0: ord('w'),
    0xba: ord('.'),
    0x18: ord('b'),
    0x8b: ord('W'),
    0x5e: ord('T'),

    0xd1: ord('N'),
    0xc3: ord('R'),
    0x36: ord('S'),

    0xcd: ord('%'),
    0x41: ord('L'),
    0xe2: ord('\n'),

    0x90: 0x05,
    0x9b: 0x8b,
    0xe1: 0x01,

    0xd5: 0xfc, # ?

    0xc0: 0xf4, # ?
    0xc1: 0xc2, # ?

    # rand
    0x46: 0xd3,
    0xda: 0x5a,

    0x0f: 0xfb,

    0x4d: 0x0c,
    0x34: 0x34,
    0xbf: 0xf9,
    0x68: 0x9d,
    0xed: 0x7f,

    0x0d: 0x0f, # two byte opcode
    0xc8: 0x29,
}

for i in perm:
  j = perm[i]
  print("%02x %02x %s" % (i, j, "" if real_perm[i] == j else "WRONG"))

print("len", len(perm))


from collections import Counter
c = Counter(sec_bytes)
for a, b in c.most_common(30):
    cc = "?"
    if a in perm:
        cc = hex(perm[a])
    print(hex(a), b, cc)

c = Counter(zip(sec_bytes, sec_bytes[1:]))
for a, b in c.most_common(30):
    ccc = []
    for x in a:
        cc = "?"
        if x in perm:
            cc = hex(perm[x])
        ccc.append(cc)
    a = [hex(x) for x in a]
    print(a, b, ccc)

c = Counter(zip(sec_bytes, sec_bytes[1:], sec_bytes[2:]))
for a, b in c.most_common(30):
    ccc = []
    for x in a:
        cc = "?"
        if x in perm:
            cc = hex(perm[x])
        ccc.append(cc)
    a = [hex(x) for x in a]
    print(a, b, ccc)

c = Counter(zip(sec_bytes, sec_bytes[1:], sec_bytes[2:], sec_bytes[3:]))
for a, b in c.most_common(30):
    ccc = []
    for x in a:
        cc = "?"
        if x in perm:
            cc = hex(perm[x])
        ccc.append(cc)
    a = [hex(x) for x in a]
    print(a, b, ccc)


bit_known = []
unknown = []
new_bytes = []
new_bytes2 = []
for b in sec_bytes:
  if b in perm:
      new_bytes.append(perm[b])
      new_bytes2.append(perm[b])
      bit_known.append(1)
  else:
      unknown.append(b)
      new_bytes.append(0xcc)
      new_bytes2.append(b)
      bit_known.append(0)

c = Counter(unknown)
print("Unknown:", len(unknown), "out of", len(sec_bytes))
for a, b in c.most_common(30):
  print(hex(a), b)


old_file = open(sys.argv[1], "rb").read()

new_file = old_file[:off] + bytes(new_bytes) + old_file[off + len(sec_bytes):]
new_file2 = old_file[:off] + bytes(new_bytes2) + old_file[off + len(sec_bytes):]

open("decrypted", "wb").write(new_file)
open("decrypted2", "wb").write(new_file2)

state = 0
def xorshift64():
  global state
  x = state
  x ^= x << 7
  x &= 2**64-1
  x ^= x >> 9
  x &= 2**64-1
  state = x
  return state

flag = b"CTF{l0oks_l1k3_x86p3rm_pr07ector_i5_n0t_5ecur3}"
results = []
#for i in range(1):
for i in range(100000):
  start = random.randint(0, 2**64-1)
  state = start
  j = 0
  sm = 0
  st = set()
  ar = []
  indxs = []
  while True:
    x2 = xorshift64()
    x = x2 % 10000
    if not bit_known[x]: break
    sm += new_bytes[x]
    ar.append(new_bytes[x])
    indxs.append(x2)
    st.add(new_bytes[x])
    j += 1
  results.append((j, start, sm, st, ar, indxs))

all_st = set()
for idx, (i, j, sm, st, ar, indxs) in enumerate(sorted(results)[::-1][:len(flag)]):
  print("{%d, %dULL, %d}," % (i, j, flag[idx] - sm))
#  print(ar, sum(ar), sm, indxs)
  all_st |= st

print("Needed:", len(all_st))
print("flaglen", len(flag))




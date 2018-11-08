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
import os
import random
import hashlib

# Utils to split a key into N parts (one needs all N parts to decrypt).
def split_single(v):
  v = bytearray(v)
  k1 = bytearray(os.urandom(len(v)))
  k2 = bytearray([a^b for a, b in zip(v, k1)])
  return [k1, k2]

def split(v, count):
  assert count >= 2

  keys = []
  while len(keys) < count:
    if not keys:
      keys += split_single(v)
      continue

    idx = random.randint(0, len(keys) - 1)
    vc = keys.pop(idx)
    keys += split_single(vc)

  #print count, keys
  return keys


def merge(keys):
  assert len(set([len(k) for k in keys])) == 1
  res = bytearray(len(keys[0]))

  keys = [bytearray(k) for k in keys]

  for i in xrange(len(keys[0])):
    for k in keys:
      res[i] ^= k[i]

  return res

def gen_arm(key):
  def hash32(v):
    v = ord(v)
    prime1 = 1043845471
    prime2 = 2031611221
    prime3 = 3304597063
    step1 = (v * prime1 + prime3) & 0xffffffff
    step2 = step1 % prime2
    return step2
    #return step1

  key = str(key).encode('hex')
  consts = ["0x%x" % hash32(v) for v in key]

  with open("consts_arm.h", "wb") as f:
    print>>f, "#include <stdint.h>"
    print>>f, "uint32_t CONSTS[] = {"
    print>>f, ",".join(consts)
    print>>f, "};"

def gen_mips(key):
  class MSWS:
    def __init__(self):
      self.x = 0
      self.w = 0
      self.s = 0xb5ad4eceda1ce2a9
      self.MASK = (2**64-1)

    def gen(self):
      self.x *= self.x
      self.x &= self.MASK

      self.w += self.s
      self.w &= self.MASK

      self.x += self.w
      self.x &= self.MASK

      self.x = (self.x >> 32) | (self.x << 32)
      self.x &= self.MASK

      return self.x & 0xff

  msws = MSWS()

  key = str(key).encode('hex')
  consts = ["%i" % (msws.gen() ^ ord(v)) for v in key]

  with open("consts_mips.h", "wb") as f:
    print>>f, "#include <stdint.h>"
    print>>f, "uint8_t CONSTS[] = {"
    print>>f, ",".join(consts)
    print>>f, "};"

def gen_x86(key):
  bits = range(32 * 8)
  random.shuffle(bits)
  mixer = [((b << 1) | random.randint(0, 1)) for b in bits]
  mixers = ["%i" % v for v in mixer]

  key = bytearray(str(key).encode('hex'))

  def mix(src, mixer):
    dst = bytearray(len(src))

    for i in xrange(32 * 8):
      src_idx = mixer[i] >> 1
      src_bit = src_idx % 8
      src_byte = src_idx / 8

      bit = (src[src_byte] >> src_bit) & 1

      if mixer[i] & 1:
        bit ^= 1

      dst_bit = i % 8
      dst_byte = i / 8

      dst[dst_byte] |= bit << dst_bit
    return dst

  enc = mix(key, mixer)
  consts = ["%i" % x for x in enc]

  with open("consts_x86.h", "wb") as f:
    print>>f, "#include <stdint.h>"
    print>>f, "uint8_t CONSTS[] = {"
    print>>f, ",".join(consts)
    print>>f, "};"
    print>>f, "uint16_t MIXER[] = {"
    print>>f, ",".join(mixers)
    print>>f, "};"

def gen_ppc(key):
  key = str(key).encode('hex')
  mixer = range(32)
  random.shuffle(mixer)
  mixers = ["%i" % v for v in mixer]

  output = ''.join([key[i] for i in mixer])

  with open("consts_ppc.h", "wb") as f:
    print>>f, "#include <stdint.h>"
    print>>f, "const char *KEY=\"%s\";" % output
    print>>f, "uint8_t MIXER[] = {"
    print>>f, ",".join(mixers)
    print>>f, "};"

def gen_sparc(key):
  key = str(key).encode('hex')

  s = ""
  for i in xrange(32):
    s += hashlib.md5(key[:i+1]).digest()

  values = ["%i" % ord(v) for v in s]

  with open("consts_sparc.h", "wb") as f:
    print>>f, "#include <stdint.h>"
    print>>f, "uint8_t CONSTS[] = {"
    print>>f, ",".join(values)
    print>>f, "};"

def gen_s390(key):
  key = str(key).encode('hex')

  def enc(v):
    v = ord(v)
    return v * 13 + 37

  values = ["%i" % enc(v) for v in key]

  with open("consts_s390.h", "wb") as f:
    print>>f, "#include <stdint.h>"
    print>>f, "uint32_t CONSTS[] = {"
    print>>f, ",".join(values)
    print>>f, "};"

FLAG = "CTF{puzzlements}"
assert len(FLAG) == 16

names = [
    "ARM",
    "MIPS",
    "X86",
    "PPC",
    "SPARC",
    "S390"
]
keys = split(FLAG, len(names))

with open("keys.backup", "w") as f:
  for i in xrange(len(names)):
    print>>f, "Key %-5s: %s" % (names[i], str(keys[i]).encode("hex"))

for key, gen in zip(keys, [
    gen_arm,
    gen_mips,
    gen_x86,
    gen_ppc,
    gen_sparc,
    gen_s390]):
  gen(key)





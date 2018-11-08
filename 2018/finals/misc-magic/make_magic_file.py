#!/usr/bin/env python2
"""
Copyright 2018 Google LLC

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    https://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
"""

import subprocess, sys, struct, random, operator

"""
flag file layout:

64byte flag, padded with 0bytes

16 byte copied & scrambled flag hex chars

8 byte xor of the two quads
"""

B64 = (1 << 64) - 1

# this makes debugging easier
random.seed(0xffffff & 6128746871632846182764)

# obfuscates the "function" or state names to be binary and randomize the id
num_states = 114 #found by running once :)
state_obfuscation = range(num_states)
random.shuffle(state_obfuscation)
def encode_state(s):
  assert s < len(state_obfuscation)
  s = state_obfuscation[s]
  return "".join("\\%s" % oct(ord(c)) for c in struct.pack("Q", s).rstrip("\x00"))

flag = "CTF{7c45af463b296bfd5ae2f5305bc9e649}"
flagfile = flag.ljust(64, "\x00")

lines_ = []
line = lines_.append
fail = 0
good = 1

# test the first 4 bytes and the last byte
line("#start")
line("0 byte x")
line("!:strength + 255")
line(">0 lelong %d" % struct.unpack("<I", flag[:4]))
line(">>%d lelong %d" % (flag.find("}"), ord("}")))
line(">>>%d lequad 0" % (flag.find("}") + 4))
line(">>>>%d lequad 0" % (flag.find("}") + 4 + 8))
line(">>>>>%d lequad 0" % (flag.find("}") + 4 + 16))
line(">>>>>>0 use %s" % encode_state(good))
line(">>>>>0 default x")
line(">>>>>>0 use %s" % encode_state(fail))
line(">>>>0 default x")
line(">>>>>0 use %s" % encode_state(fail))
line(">>>0 default x")
line(">>>>0 use %s" % encode_state(fail))
line(">>0 default x")
line(">>>0 use %s" % encode_state(fail))
line(">0 default x")
line(">>0 use %s" % encode_state(fail))

line("#fail")
line("0 name %s" % encode_state(fail))
line(">0 byte 0")
line(">>0 byte 1 ...")

# transfer the hex chars
# define the bits that are assigned for each hex char
l = range(128)
random.shuffle(l)
masks_per_hex = [reduce(operator.or_, map(lambda n: 1<<n, l[pos * 4:][:4]), 0) for pos in xrange(32)]
wanted_constant = 0
for pos in xrange(32):
  correct_hex = flag[pos + 4]
  mask = masks_per_hex[pos]
  vals = [0]
  for _ in xrange(15):
    vals.append((vals[-1] - 1) & mask)
  random.shuffle(vals)

  line("0 name %s" % encode_state(good))
  good += 1

  for v, c in zip(vals, "0123456789abcdef"):
    if c == correct_hex:
      assert not mask & wanted_constant
      wanted_constant |= v
    line(">%d byte %d" % (pos + 4, ord(c)))
    if mask & B64:
      line(">>64 lequad&%d %d" % (mask & B64, v & B64))
    else:
      line(">>0 byte x")
    if mask >> 64:
      line(">>>72 lequad&%d %d" % (mask >> 64, v >> 64))
    else:
      line(">>>0 byte x")
    line(">>>>0 use %s" % encode_state(good))
    line(">>>0 default x")
    line(">>>>0 use %s" % encode_state(fail))
    line(">>0 default x")
    line(">>>0 use %s" % encode_state(fail))

  line(">0 default x")
  line(">>0 use %s" % encode_state(fail))

# xor every bit from first part with second part, make sure it is = third part
for i in xrange(64):
  line("0 name %s" % encode_state(good))
  good += 1

  m = 1 << i

  line(">64 lequad&%d %d" % (m, 0))

  line(">>72 lequad&%d %d" % (m, 0))
  line(">>>80 lequad&%d %d" % (m, 0))
  line(">>>>0 use %s" % encode_state(good))
  line(">>>80 lequad&%d %d" % (m, m))
  line(">>>>0 use %s" % encode_state(fail))

  line(">>72 lequad&%d %d" % (m, m))
  line(">>>80 lequad&%d %d" % (m, m))
  line(">>>>0 use %s" % encode_state(good))
  line(">>>80 lequad&%d %d" % (m, 0))
  line(">>>>0 use %s" % encode_state(fail))

  line(">64 lequad&%d %d" % (m, m))

  line(">>72 lequad&%d %d" % (m, 0))
  line(">>>80 lequad&%d %d" % (m, m))
  line(">>>>0 use %s" % encode_state(good))
  line(">>>80 lequad&%d %d" % (m, 0))
  line(">>>>0 use %s" % encode_state(fail))

  line(">>72 lequad&%d %d" % (m, m))
  line(">>>80 lequad&%d %d" % (m, 0))
  line(">>>>0 use %s" % encode_state(good))
  line(">>>80 lequad&%d %d" % (m, m))
  line(">>>>0 use %s" % encode_state(fail))

# compare the 16 bytes starting at offset 72 with a constant
wanted_constant = struct.pack("QQQ", wanted_constant & B64, wanted_constant >> 64, (wanted_constant & B64) ^ (wanted_constant >> 64))
flagfile += wanted_constant
for char, pos in zip(map(ord, wanted_constant[8:]), xrange(72, 72 + 16)):
  line("0 name %s" % encode_state(good))
  good += 1

  line(">%d byte %d" % (pos, char))
  line(">>0 use %s" % encode_state(good))

# the final good state
line("0 name %s" % encode_state(good))
line(">0 regex \^CTF[{]\.{32}[}] The flag: %s")

# shuffle the "functions"
functions = []
for l in lines_:
  if not l:
    continue
  if l[0] in ">!":
    functions[-1].append(l)
  else:
    functions.append([l])
random.shuffle(functions)

def compile_mgc(mgc):
  tmpdir = subprocess.check_output(["/bin/sh", "-c", "mktemp -d /tmp/XXXXXXXX"]).strip()
  open("%s/magic" % tmpdir, "wb").write(mgc)
  subprocess.check_output(["/bin/sh", "-c", "cd '%s'; file -C -m magic" % tmpdir])
  compiled_mgc = open("%s/magic.mgc" % tmpdir).read()
  subprocess.check_output(["/bin/sh", "-c", "rm -rf '%s'" % tmpdir])
  return compiled_mgc

lines_ = sum(functions, [])
compiled_mgc = compile_mgc("\n".join(lines_) + "\n")

sys.stdout.write(compiled_mgc if sys.argv[-1] != "--flag" else flagfile)

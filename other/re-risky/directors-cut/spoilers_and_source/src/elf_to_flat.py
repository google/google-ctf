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
import sys
import subprocess
import os

TARGET = "riscv64-unknown-elf-"

if len(sys.argv) != 2:
  sys.exit("usage: elf_to_flag.py <elf>")

def whitespace_split(s):
  s = s.replace("\t", " ")
  return [x for x in s.split(" ") if x]

def read_program_header(fname):
  output = subprocess.check_output([
    TARGET + "objdump",
    "-x",
    fname
  ]).splitlines()

  ph = []

  for i, ln in enumerate(output):
    if not ln.startswith("Program Header:"):
      continue

    j = i + 1
    while True:
      ln = output[j].strip()
      if not ln:
        break

      ln1 = whitespace_split(ln)
      j += 1
      ln2 = whitespace_split(output[j].strip())
      j += 1

      if ln1[0] != "LOAD":
        print "skipping", ln1[0]
        continue

      ph.append({
        "off": int(ln1[2], 16),
        "vaddr": int(ln1[4], 16),
        "filesz": int(ln2[1], 16),
        "memsz": int(ln2[3], 16),
      })
    break

  return ph

def memcpy(dst, dst_idx, src, src_idx, sz):
  for i in range(sz):
    dst[dst_idx + i] = src[src_idx + i]

fname = sys.argv[1]

ph = read_program_header(fname)
elf = bytearray(open(fname, "rb").read())

sz = ph[-1]["vaddr"] + max(ph[-1]["filesz"], ph[-1]["memsz"])
sz = (sz + 0xfff) & 0xfffff000  # Align.
sz += 0x1000  # Front padding.

print "final size: 0x%x" % sz
flat = bytearray(sz)
for h in ph:
  print "copying 0x%x bytes from 0x%x to 0x%x" % (h["filesz"], h["off"], h["vaddr"])
  memcpy(flat, h["vaddr"], elf, h["off"], h["filesz"])

name = os.path.basename(fname)
name = os.path.splitext(name)[0] + ".flat"

open(name, "wb").write(flat[0x1000:])  # Don't write front padding.



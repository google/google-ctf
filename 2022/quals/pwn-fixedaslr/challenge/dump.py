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
# Just a simple dumper to double-check there are no stack pointers in non-stack
# space.
import sys
import struct

if len(sys.argv) != 2:
  sys.exit("usage: dump.py <pid>")

pid = int(sys.argv[1])

with open(f"/proc/{pid}/maps") as f:
  lines = f.read().splitlines()

MASK       = 0xffffff0000000000
STACK_MASK = 0xffffff0000000000
STACK_ADDR = 0x00007f0000000000
with open(f"/proc/{pid}/mem", "rb") as f:
  for ln in lines:
    r = ln.split()[0]
    r = r.split('-')
    start = int(r[0], 16)
    end = int(r[1], 16)
    sz = end - start

    if start & MASK:
      print(f"Skipping 0x{start:x}")
      continue

    print(f"Checking 0x{start:x} of size 0x{sz:x}...")

    f.seek(start)
    d = f.read(sz)
    ptr_cnt = sz // 8
    ptrs = struct.unpack(f"<{ptr_cnt}Q", d)
    for p in ptrs:
      if (p & STACK_MASK) == STACK_ADDR:
        print(f"  0x{p:x}")

print("Done.")

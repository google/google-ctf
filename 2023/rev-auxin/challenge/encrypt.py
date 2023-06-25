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

keys = [
    0xda49,
    0x5b02,
    0x2c2b,
    0xfb27,
    0x3ec3,
    0x18e8,
    0x13aa,
    0x70f5,
    0x8995
]

with open('auxin.rom.sym','rb') as f:
    s = f.read()

syms = {}
while len(s) > 0:
    addr = s[0]*256 + s[1]
    s = s[2:]
    name = b''
    while s[0] != 0:
        name += bytes([s[0]])
        s = s[1:]
    s = s[1:]
    name = name.decode('ascii')
    syms[name] = addr

with open('auxin.rom','rb') as f:
    rom = bytearray(f.read())

for i in range(9):
    start = syms[f'check_flag/chunk{i}'] - 0x100
    end = syms[f'check_flag/chunk{i+1}'] - 0x100
    seed = keys[i]
    for addr in range(start, end):
        rom[addr] ^= seed & 0xFF
        seed = (seed ^ (seed << 7)) & 0xFFFF
        seed = (seed ^ (seed >> 9)) & 0xFFFF
        seed = (seed ^ (seed << 8)) & 0xFFFF

with open('auxin.rom','wb') as f:
    f.write(bytes(rom))

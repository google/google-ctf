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
# Just a helper script to find a place which can be used to redirect the pc to
# the shellcode.
#
with open("dumpfirmware", "rb") as f:
  data = bytearray(f.read())

needle = [0x02, 0x0a, 0x80]  # LJMP 0xA80

i = 0
while i < len(data) - len(needle) + 1 and i < 0xa00:
  if all([(a & b) == b for a, b in zip(data[i:i+len(needle)], needle)]):
    print(f"Candidate: 0x{i:04x}")

  i += 1



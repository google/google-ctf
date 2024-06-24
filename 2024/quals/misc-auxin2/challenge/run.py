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

import subprocess
import sys

MAX_LEN = 0x70 # our solution is 92 bytes ;)

s = input('input: ').strip()

if not s or len(s) % 2 or not all(i in '0123456789abcdef' for i in s):
  print('bad input.')
  sys.exit(1)

if len(s) // 2 > MAX_LEN:
  print('too long!')
  sys.exit(1)

try:
    p = subprocess.run(['./uxncli', 'auxin2.rom', s], timeout=0.5, capture_output=True)
    if p.stdout:
        print(p.stdout[:0x100])
except subprocess.TimeoutExpired as e:
    print('timeout!')
    if e.stdout:
        print(e.stdout[:0x100])

#!/usr/bin/env python3
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

import pwnlib.tubes

def handle_pow(r):
    print(r.recvuntil(b'python3 '))
    print(r.recvuntil(b' solve '))
    challenge = r.recvline().decode('ascii').strip()
    p = pwnlib.tubes.process.process(['kctf_bypass_pow', challenge])
    solution = p.readall().strip()
    r.sendline(solution)
    print(r.recvuntil(b'Correct\n'))

r = pwnlib.tubes.remote.remote('127.0.0.1', 1337)
print(r.recvuntil(b'== proof-of-work: '))
if r.recvline().startswith(b'enabled'):
    handle_pow(r)

r.recvuntil(b'input: ')
r.sendline(b'efef3921212fefefefa5a5a53a3a3a3a3a3a3a3a840494cfcf1a01190505152194cfcfcf8484011a011a1a1a011a1a0da528058509442babd41d99850a1d0a0a1a85adbcd41dbcd41d3c090999851d1c85158509241d992504f50505050505056b71616c')

print(r.recvuntil(b'CTF{'))
print(r.recvuntil(b'}'))

exit(0)

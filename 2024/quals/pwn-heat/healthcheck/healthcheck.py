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
import pwnlib.util.misc
import base64

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

module_builder = pwnlib.util.misc.read("/home/user/wasm-module-builder.js")
exploit = pwnlib.util.misc.read("/home/user/exploit.js")

b64 = base64.b64encode(module_builder + b'\n' + exploit)

r.recvuntil(b'How many bytes is your base64-encoded exploit? ')
r.sendline(str(len(b64)))

r.recvuntil(b'Exploit as base64 please')
r.send(b64)

print(r.recvuntil(b'CTF{'))
print(r.recvuntil(b'}'))

exit(0)

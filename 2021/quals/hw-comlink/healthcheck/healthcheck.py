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

import pwnlib

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

with open('/home/user/firmware.ihx', 'r') as fin:
    firmware = fin.read()

#print('Send firmware')
r.recvline_contains('IHex:')
r.sendline(firmware)
r.recvline_contains('Capturing radio transmission from device:')

#print('Send input')
payload = b'X'*32
r.sendline(payload)

#print('Recv result')
res = r.recvuntil('\nExecution completed')[:-20]
#print(res.hex(), len(res), res)
assert res == bytes.fromhex('260923f7fc940805c0306f9d273299bbca8ca2d6d1f5b4a491b953de76e8f89e65b7c76ac121e9b172f6ff8d6458cfd6')

exit(0)

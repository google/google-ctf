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
import struct

def handle_pow(r):
    print(r.recvuntil(b'python3 '))
    print(r.recvuntil(b' solve '))
    challenge = r.recvline().decode('ascii').strip()
    p = pwnlib.tubes.process.process(['kctf_bypass_pow', challenge])
    solution = p.readall().strip()
    r.sendline(solution)
    print(r.recvuntil(b'Correct\n'))

def try_flag(flag_id: str):
    r = pwnlib.tubes.remote.remote('127.0.0.1', 1337)
    if r.recvline().startswith(b'enabled'):
        handle_pow(r)

    with open("/home/user/get_flag_%s.inp" % flag_id, "rb") as f:
        input_bytes = f.read()
    r.send(struct.pack(">I", len(input_bytes)))
    r.send(input_bytes)
    print("Sent input, waiting for flag", flag_id)
    while True:
        if b'CTF{' in r.recvline():
            print("Got flag", flag_id)
            break

try_flag("a")
try_flag("b")
exit(0)

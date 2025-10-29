#!/usr/bin/env python3
# Copyright 2025 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.


import socket
import subprocess


def recv_until(s, end, keep=True):
  buf = b''
  while True:
    buf += s.recv(1)
    if buf.endswith(end):
      if keep:
        return buf
      else:
        return buf[:-len(end)]


def handle_pow(s):
  recv_until(s, b'python3 ')
  recv_until(s, b' solve ')

  challenge = recv_until(s, b'\n').decode('ascii').strip()
  print(challenge)
  solution = subprocess.check_output(['kctf_bypass_pow', challenge])
  s.sendall(solution + b'\n')
  print(recv_until(s, b'Correct\n'))


s = socket.create_connection(('localhost', 1337))
s.settimeout(15)

recv_until(s, b'== proof-of-work: ')
if recv_until(s, b'\n').startswith(b'enabled'):
  handle_pow(s)

recv_until(s, b'~ $')
s.sendall(b'while true; do ( cat /flag.txt & ); done\n')

recv_until(s, b'CTF{')
print(recv_until(s, b'}', keep=False))

exit(0)

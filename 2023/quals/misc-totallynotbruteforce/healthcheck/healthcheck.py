#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Copyright 2023 Google LLC
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
import h2.connection
import h2.events


def handle_pow(r):
    print(r.recvuntil(b'python3 '))
    print(r.recvuntil(b' solve '))
    challenge = r.recvline().decode('ascii').strip()
    p = pwnlib.tubes.process.process(['kctf_bypass_pow', challenge])
    solution = p.readall().strip()
    r.sendline(solution)
    print(r.recvuntil(b'Correct\n'))


r = pwnlib.tubes.remote.remote('127.0.0.1', 1337)
print(r.recvuntil(b'== proof-of-work: '))
if r.recvline().startswith(b'enabled'):
    handle_pow(r)

c = h2.connection.H2Connection()
c.initiate_connection()
r.send(c.data_to_send())
headers = [
    (':method', 'GET'),
    (':path', '/status'),
    (':authority', '127.0.0.1:1337'),
    (':scheme', 'https'),
]
c.send_headers(1, headers, end_stream=True)
r.send(c.data_to_send())

body = b''
response_stream_ended = False
while not response_stream_ended:
    data = r.recv(65536 * 1024)
    if not data:
        break

    events = c.receive_data(data)
    for event in events:
        if isinstance(event, h2.events.DataReceived):
            c.acknowledge_received_data(event.flow_controlled_length, event.stream_id)
            body += event.data
        if isinstance(event, h2.events.StreamEnded):
            response_stream_ended = True
            break

    r.send(c.data_to_send())

c.close_connection()
r.send(c.data_to_send())

print('received:', body.decode())
if 'ok' in body.decode():
  exit(0)
else:
  exit(1)

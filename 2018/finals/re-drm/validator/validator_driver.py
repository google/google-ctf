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

__author__      = "Ian Eldred Pudney"

import sys
import tempfile
import struct
import os
import subprocess

print "Please send a 4-byte little-endian integer specifying the size of your solution, followed by the solution itself."
sys.stdout.flush()

payload_size_str = sys.stdin.read(4)
payload_size = struct.unpack("<L", payload_size_str)[0]

print "Waiting for " + str(payload_size) + " solution bytes."
sys.stdout.flush()

payload = sys.stdin.read(payload_size)

print "Received " + str(len(payload)) + " payload bytes."
sys.stdout.flush()

with tempfile.NamedTemporaryFile("wb", delete=False) as f:
  f.write(payload)
  name = f.name

os.chmod(name, 0700)

subprocess.call(["/usr/bin/python2.7", "-u", "validator.py", name])


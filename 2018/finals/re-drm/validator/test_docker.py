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

# example usage: python test_docker.py ../challenge/solution <container>

import struct
import sys
import subprocess

with open(sys.argv[1], "rb") as f:
  payload = f.read()
  payload_size = len(payload)
  print "payload size: " + str(payload_size)

payload_size_str = struct.pack("<L", payload_size)

process = subprocess.Popen(["docker", "run", "-i", "--cap-add=SYS_PTRACE", sys.argv[2]], executable="docker", stdin=subprocess.PIPE)
process.stdin.write(payload_size_str)
process.stdin.write(payload)
process.wait()

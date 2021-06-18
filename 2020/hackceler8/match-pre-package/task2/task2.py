#!/usr/bin/python3
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
import sys
import os

FLAG = os.environ["TASK2_FLAG"]

print("""
This isn't really a challenge, it's just a way to make sure everyone knows how
to send binary data to a challenge.

Send the following binary data my way: 00 FF 99 11
""")
sys.stdout.flush()

data = b''
while len(data) < 10:
  new_data = sys.stdin.buffer.read(1)
  data += new_data

  if b"\x00\xff\x99\x11" in data:
    print("Awesome, here's your flag:")
    print(FLAG)
    sys.stdout.flush()
    sys.exit(0)

print("Nope, it didn't work")

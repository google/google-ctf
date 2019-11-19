#! /usr/bin/python3

# Copyright 2019 Google LLC
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

import base64
import vmac64
import struct
import random
import sys
# This is definitely not random

def gen_random_bytes(len):
  ran = random.randrange(10**80)
  myhex = "%032x" % ran
  return myhex[:len]

def generate_collission(key):
  key = bytes.fromhex(key)
  nonce = bytes.fromhex(gen_random_bytes(16))
  mac = vmac64.Vmac64(key)
  saved_msgs = []
  inp = [None, None]
  for i in range(len(inp)):
    inp[i] = (0 - mac.l1_keys[i]) % 2**64
  msg = b"".join(struct.pack("<Q", v) for v in inp)
  msg_critical = msg[:8]
  saved_msgs.append(msg)
  print("Collision!")
  print(bytes.hex(nonce + mac.tag(msg, nonce) + msg_critical))

if __name__ == "__main__":
  if len(sys.argv) != 2:
    print("Must pass in key to generate collision for")
  key = sys.argv[1]
  assert len(key) == 32, "Key must be 32 hex characters"
  generate_collission(key)

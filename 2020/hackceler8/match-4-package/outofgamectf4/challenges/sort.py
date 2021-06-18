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
import random
import struct
import os

banner = """
Your task is to sort a list of u64 integers.
rdi points to a rw mapping with the following data:
  u64 num
  u64 data[num]
when sorted, write the result to stdout.
"""

flag = "HCL8{it_is_s0r73D!}"

def make_challenge():
  num = random.randrange(32, 256)
  data = os.urandom(num * 8)
  data_sorted = struct.pack("Q"*num, *sorted(struct.unpack("Q"*num, data)))
  return data_sorted, struct.pack("Q", num) + data

def check(expected, result):
  return expected == result

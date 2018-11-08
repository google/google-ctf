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

import hashlib
import sys
import tempfile

import hash_asparagus

real_serial = "this-is-not-the-goal-of-the-challenge"
with tempfile.NamedTemporaryFile("wb", delete=False) as f:
  fname = f.name
  with open("infile", "r") as infile:
    h = hash_asparagus.run_asparagus(sys.argv[1], real_serial, infile, f, False)

with open(fname, "rb") as f:
  with open("expected", "wb") as g:
    for line in f.readlines():
      if line[-1] == "\n":
        line = line[0:-1]
      g.write(hash_asparagus.shash(line) + "\n")

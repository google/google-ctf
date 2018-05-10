#!/usr/bin/env python2.7
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



from hashcash import check
import random
import string
import sys
import os

SKIP_SECRET = "letmein_prettyplease1337"

bits = 28
resource = "".join(random.choice(string.ascii_lowercase) for i in range(8))
print("hashcash -mb{} {}".format(bits, resource))
sys.stdout.flush()

stamp = sys.stdin.readline().strip()

if stamp != SKIP_SECRET:
  if not stamp.startswith("1:"):
    print("only hashcash v1 supported")
    exit(1)

  if not check(stamp, resource=resource, bits=bits):
    print("invalid")
    exit(1)

os.execv(sys.argv[1], sys.argv[1:])

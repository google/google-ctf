#!/usr/bin/python
# Copyright 2018 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http:#www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
import hashlib
FLAG = 'flag{4rg3n7um-47}'
HASH_TEMPLATE = '['
for ch in FLAG:
  HASH_TEMPLATE += '"%s"' % hashlib.sha256("SUFFIX" + ch + "PREFIX").hexdigest()
  HASH_TEMPLATE += ','
HASH_TEMPLATE += ']'

d = open("checker.py.template").read()
out = d.replace('HASH_TEMPLATE', HASH_TEMPLATE)

f = open("checker.py", "w")
f.write(out)
f.close()



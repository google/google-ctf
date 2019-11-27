#!/usr/bin/python
# Copyright 2018 Google LLC
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
d = open("risky.py.template").read().splitlines()

loader = bytearray(open("loader.pyc", "rb").read()[8:].encode('zlib'))

o = []
for ln in d:
  #if ln.strip().startswith('#'):
  #  continue
  if not ln.strip():
    continue
  if ln == '"LOADER_TEMPLATE"':
    txt = "loader = '"
    txt += ''.join(["\\x%.2x" % x for x in loader])
    txt += "'.decode('zlib')"
    o.append(txt)
    continue

  o.append(ln)

out = '\n'.join(o)
#out = '# -*- coding: rot13 -*-\n' + out.encode('rot13')
f = open("risky.py", "w")
f.write(out)
f.close()



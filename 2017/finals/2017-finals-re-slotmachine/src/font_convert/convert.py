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

"""
Bad hax :/ I know
"""
with open("5x7.bdf", 'r') as f:
    content = f.read().split("\n\n")

vals = {}

for definition in content[3:]:
    bmap = []
    e = None
    in_bmap = False
    for d in definition.split("\n"):
        if not in_bmap:
            if d == 'BITMAP':
                in_bmap = True
                continue
            elif d == 'ENDFONT':
                break
            k, v = d.split(' ', 1)
            if k == 'ENCODING':
                e = int(v)
        else:
            if d == 'ENDCHAR':
                break
            else:
                bmap.append(int(d, 16))
    if not e:
        continue
    """
    The bitmap here is organized as [line1] [line2] [line3] ...
    We have a 5x7 font, so we're able to swap the dimensions to safe some bytes
    [col1] [col2] [col3] ...
    """
    r = [0, 0, 0, 0, 0]
    for y in range(7):
        for x in range(5):
            if bmap[y] & (1 << (7 - x)):
                r[x] |= (1 << y)

    if e >= 0x20 and e <= 0x7F:
        vals[e] = r

with open('out', 'w') as f:
    for k, v in vals.items():
        values = ', '.join(["0x{:02X}".format(i) for i in v])
        f.write("    {{{}}}, // '{}'\n".format(values, chr(k)))


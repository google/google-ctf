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

try:
    import Image
    import ImageDraw
except ImportError:
    from PIL import Image
    from PIL import ImageDraw
import sys

def chunks(l, n):
    for i in range(0, len(l), n):
        yield l[i:i + n]

if len(sys.argv) != 2:
    print 'Usage: {} <flag>'.format(sys.argv[0])

txt = 'Congratulations!\n  The flag is:\n{}'.format(sys.argv[1])
image = Image.new('RGBA', (128, 64), (0, 0, 0))
draw = ImageDraw.Draw(image)
draw.text((3, 0), txt, (255, 255, 255))

res = []
for pixels in chunks(list(image.getdata()), 8):
    byte = ['1' if x[0] == 255 else '0' for x in pixels]
    res.append(int("".join(byte), 2))

line = '{'
for b in res:
    line += '{}, '.format(hex(b))
line += '}'

with open('bitmaps_tmpl.h') as f:
    content = f.read().replace('__REPLACE_WITH_FLAG__', line)
with open('bitmaps.h', 'w') as f:
    f.write(content)

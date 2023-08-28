#!/usr/bin/env python3

# Copyright 2023 Google LLC
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

from pathlib import Path

patterns_out = Path('patterns')
patterns_out.mkdir(exist_ok=True)
patterns_in = Path('patterns-src')

def rotate(pattern):
    lines = pattern.strip().split()
    assert all(len(line) == len(lines[0]) for line in lines)
    res = [[] for _ in range(len(lines[0]))]
    for x, line in enumerate(lines):
        for y, c in enumerate(line[::-1]):
            res[y].append(c)
    return '\n'.join(''.join(line) for line in res)
    

# LR -> UD
for f in patterns_in.glob('*-lr.txt'):
    pattern = f.read_text()
    (patterns_out / f.name).write_text(pattern)
    pattern = rotate(pattern)
    (patterns_out / f.name.replace('-lr', '-ud')).write_text(pattern)

# LD -> LU, UR, RD
for f in patterns_in.glob('*-ld.txt'):
    pattern = f.read_text()
    (patterns_out / f.name).write_text(pattern)
    pattern = rotate(pattern)
    (patterns_out / f.name.replace('-ld', '-rd')).write_text(pattern)
    pattern = rotate(pattern)
    (patterns_out / f.name.replace('-ld', '-ur')).write_text(pattern)
    pattern = rotate(pattern)
    (patterns_out / f.name.replace('-ld', '-lu')).write_text(pattern)

# R -> U, L, D
for f in patterns_in.glob('*-r.txt'):
    pattern = f.read_text()
    (patterns_out / f.name).write_text(pattern)
    pattern = rotate(pattern)
    (patterns_out / f.name.replace('-r', '-u')).write_text(pattern)
    pattern = rotate(pattern)
    (patterns_out / f.name.replace('-r', '-l')).write_text(pattern)
    pattern = rotate(pattern)
    (patterns_out / f.name.replace('-r', '-d')).write_text(pattern)

# LUD -> LRD, URD, LUR
for f in patterns_in.glob('*-lud.txt'):
    pattern = f.read_text()
    (patterns_out / f.name).write_text(pattern)
    pattern = rotate(pattern)
    (patterns_out / f.name.replace('-lud', '-lrd')).write_text(pattern)
    pattern = rotate(pattern)
    (patterns_out / f.name.replace('-lud', '-urd')).write_text(pattern)
    pattern = rotate(pattern)
    (patterns_out / f.name.replace('-lud', '-lur')).write_text(pattern)

# LUR -> LUD, LRD, URD
for f in patterns_in.glob('*-lur.txt'):
    pattern = f.read_text()
    (patterns_out / f.name).write_text(pattern)
    pattern = rotate(pattern)
    (patterns_out / f.name.replace('-lur', '-lud')).write_text(pattern)
    pattern = rotate(pattern)
    (patterns_out / f.name.replace('-lur', '-lrd')).write_text(pattern)
    pattern = rotate(pattern)
    (patterns_out / f.name.replace('-lur', '-urd')).write_text(pattern)

pattern = (patterns_in / 'crossing.txt').read_text()
(patterns_out / 'crossing.txt').write_text(pattern)

pattern = (patterns_in / 'split-lurd.txt').read_text()
(patterns_out / 'split-lurd.txt').write_text(pattern)

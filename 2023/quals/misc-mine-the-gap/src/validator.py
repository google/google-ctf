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

with open('circuit3-debug.txt', 'r') as fin:
    circuit = fin.read()
circuit = circuit.replace(' ', '0')
circuit = [list(line) for line in circuit.split('\n') if len(line) > 0]
width = len(circuit[0])
height = len(circuit)

violations = []
for y in range(height):
    for x in range(width):
        test_cell = circuit[y][x]
        if int(test_cell, 16) not in range(0, 9):
            continue

        neighbours = 0
        if y > 0 and x > 0: neighbours += int(circuit[y-1][x-1], 16) in [10, 11]
        if y > 0: neighbours += int(circuit[y-1][x], 16) in [10, 11]
        if y > 0 and x+1 < width: neighbours += int(circuit[y-1][x+1], 16) in [10, 11]

        if x > 0: neighbours += int(circuit[y][x-1], 16) in [10, 11]
        if x+1 < width: neighbours += int(circuit[y][x+1], 16) in [10, 11]

        if y+1 < height and x > 0: neighbours += int(circuit[y+1][x-1], 16) in [10, 11]
        if y+1 < height: neighbours += int(circuit[y+1][x], 16) in [10, 11]
        if y+1 < height and x+1 < width: neighbours += int(circuit[y+1][x+1], 16) in [10, 11]

        if int(test_cell, 16) != neighbours:
            violations.append((x,y))

print(violations)
print('#violations: ', len(violations))

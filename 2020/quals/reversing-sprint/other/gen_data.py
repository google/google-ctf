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

from queue import Queue
import random

random.seed(1337)
maze = [line.strip() for line in open("maze.txt").readlines()]
assert len(maze) == 16
assert len(maze[0]) == 16

def is_prime(n):
    if n == 0 or n == 1:
        return False
    for i in range(2, n):
        if n % i == 0:
            return False
    return True

primes = [i for i in range(256) if is_prime(i)]
composite = [i for i in range(256) if not is_prime(i)]

consts = []
positions = {}
for i, line in enumerate(maze):
    for j, c in enumerate(line):
        if c == '#':
            consts.append(random.choice(composite))
        else:
            consts.append(random.choice(primes))
            if c in "0123456789":
                positions[int(c)] = i*16+j

assert len(positions) == 10


dirs = {-1: 'l', 1: 'r', -16: 'u', 16: 'd'}
maze = "".join(maze)

allpaths = ""
for i in range(9):
    start = positions[i]
    end = positions[i+1]
    got_from = {}
    dist = {}
    dist[start] = 0
    q = Queue()
    q.put(start)
    while not q.empty():
        cur = q.get()
        for dir in [-1, 1, -16, 16]:
            next = cur + dir
            if next < 0 or next >= 256:
                continue
            if next in got_from:
                # Normally this would be <=, but we need unique solution.
                assert dist[next] < dist[cur] + 1
                continue
            if maze[next] == '#':
                continue
            got_from[next] = (cur, dirs[dir])
            dist[next] = dist[cur] + 1
            q.put(next)
    
    path = ""
    while end != start:
        next, dir = got_from[end]
        path += dir
        end = next

    allpaths += path[::-1]

print("Final solution (length %d, max flag length %d):" %
        (len(allpaths), len(allpaths)//4))
print(allpaths)

FLAG = "CTF{n0w_ev3n_pr1n7f_1s_7ur1ng_c0mpl3te}"
print("The flag is %s (length: %d)" % (FLAG, len(FLAG)))
enc = []
for i, c in enumerate(FLAG):
    key = allpaths[i*4:i*4+4].replace("u", "00").replace("r", "01").replace(
            "d", "10").replace("l", "11")
    key = int(key, 2)
    enc.append((ord(c)-key)%256)

print(".org 0xf000")
print("maze:")
print(".db " + " ".join(str(i) for i in consts))
print("start:")
print(".dw " + str(positions[0]))
print("negpositions:")
print(".db " + " ".join(str(-positions[c]) for c in sorted(positions)))
print("enc_flag:")
print(".db " + " ".join(str(e) for e in enc))
print(".equ minus_flag_len " + str(-len(FLAG)))
print(".equ passlength " + str(len(allpaths)))

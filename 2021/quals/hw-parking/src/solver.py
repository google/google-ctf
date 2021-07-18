# Copyright 2021 Google LLC
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

import sys, random
from pwn import *

#context.log_level = "DEBUG"

solution_file = sys.argv[1]
flagbits = sys.argv[2]
solution = int(flagbits, 2)
s = open(solution_file).read()
paths = s.split("---")
cleanpaths = []
for path in paths:
    lines = path.splitlines()
    cleanpaths.append([])
    for line in lines:
        line = line.strip()
        if not line:
            continue
        cleanpaths[-1].append(line)

cleanpaths, inputs = cleanpaths[:-1], cleanpaths[-1][0]
inputs = [int(i) for i in inputs.strip().split()]

#for solution in range(2**len(inputs)):
if 1:
    r = process(["python3", "../attachments/game.py", "../attachments/level2"], env={"DRAW":"0"})
    r.recvline()
    r.recvline()
    r.recvline()
    for bit in range(len(inputs)):
        if (solution & (1<<bit)):
            r.sendline("%d %d %d" % (inputs[bit], 0, -1))
            r.sendline("%d %d %d" % (inputs[bit], 1, 0))
            r.recvline()
            r.recvline()
            r.recvline()
            r.recvline()
            r.recvline()

    iterations_since_progress = 0
    found = False
    maxiters = 0
    totaliters = 0
    while not found:
        numdone = 0
        for path in cleanpaths:
            totaliters += 1
            maxiters = max(maxiters, iterations_since_progress)
            iterations_since_progress += 1
            #print("Trying", path)
            for move in path:
                r.sendline(move)
                s = r.recvline()
                if b"Moved" in s:
                    iterations_since_progress = 0
                    numdone += 1
                    #print("Ok!")
                elif b"collision" in s:
                    r.recvline() # Invalid
                    #print("Nope")
                    break
                else:
                    s = r.recvall()
                    print(s)
                    found = True
                    break
            if found: break
        if numdone == 0: break
        print("Done %d" % numdone)
    print(bin(solution), found)
    if found:
        print("Max", maxiters)
        print("Total", totaliters)
    r.close()



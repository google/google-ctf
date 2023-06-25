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

from PIL import Image
import sys
from z3 import *

WIDTH = 0xe89 * 8
HEIGHT = 0x23610
SIMU_HEIGHT = 1024
OFFSET = 0x3080
FUSES_X = 2896
FUSES_Y = 1057
START_X = 0x1e
START_Y = 0x1e
END_X = 0x235a5
END_Y = 0x7400

def r8(x):
    return (x >> 3) * 8

def bm_get(x, y):
    i = x * WIDTH // 8 + (y >> 3)
    return (bitmap[i] >> (y & 7)) & 1
    
def bm_set(x, y, v):
    i = x * WIDTH // 8 + (y >> 3)
    if v == 1:
        bitmap[i] = bitmap[i] | (1 << (y & 7))
    else:
        bitmap[i] = bitmap[i] & ~(1 << (y & 7))
    
def draw(fn, min_x, max_x, min_y, max_y):
    img = Image.new(mode="RGB", size=(max_y - min_y, max_x - min_x))
    pixels = img.load()

    for x in range(min_x, max_x):
        for y in range(min_y, max_y):
                if bm_get(x,y) == 1:
                    pixels[y - min_y,x - max_x] = (0,0,255)
    
    img.save(fn)

def parse():
    print("[*] Parsing the bitmap")
    fuses = [" "] * FUSES_Y
    connectors = [" "] * FUSES_Y
    gates = [" "] * FUSES_Y

    fuses_f = open('fuses.txt', 'w')
    connectors_f = open('connectors.txt', 'w')
    gates_f = open('gates.txt', 'w')

    for _x in range(FUSES_X):
        x = 50 + _x * 50
        for _y in range(FUSES_Y):
            y = 100 + _y * 28
            if bm_get(x+2,y+5) == 1:
                connectors[_y] = "c"
            else:
                connectors[_y] = " "

        prev = ""
        for _y in range(FUSES_Y):
            y = 100 + _y * 28
            if prev:
                gates[_y] = prev
                prev = ""
            elif bm_get(x+23,y+8) == 1:
                gates[_y] = "X"
                prev = "x"
            elif bm_get(x+9,y+22) == 1:
                gates[_y] = "_"
                prev = "-"
            elif bm_get(x+29,y+14) == 1:
                gates[_y] = "Y"
                prev = "y"
            elif bm_get(x+12,y+12) == 1:
                gates[_y] = "j"
            else:
                gates[_y] = "|"

        for _y in range(FUSES_Y):
            y = 100 + _y * 28
            if bm_get(x+37,y+11) == 1:
                fuses[_y] = "o"
            else:
                fuses[_y] = " "
        
        fuses_f.write("".join(fuses) + "\n")
        connectors_f.write("".join(connectors) + "\n")
        gates_f.write("".join(gates) + "\n")

def simulate(flag, iterations):
    print(f"[*] Simulating. Flag: {flag}. Iterations: {iterations}")

    img = Image.new(mode="RGB", size=(WIDTH, SIMU_HEIGHT))
    pixels = img.load()

    # Draw initial map in blue
    for x in range(SIMU_HEIGHT):
        for y in range(WIDTH):
            if bm_get(x,y) == 1:
                pixels[y,x] = (0,0,255)

    # Set flag bits in map and draw them in red
    i = 1226
    flag_idx = 0
    while i < WIDTH:
        flag_chr = flag[flag_idx]
        if flag_chr & 0x40 != 0:
            pixels[r8(i-1008) + 2, 50] = (255,0,0)
            pixels[r8(i-1008) + 3, 50] = (255,0,0)
            bm_set(50,r8(i-1008) + 2, 1)
            bm_set(50,r8(i-1008) + 3, 1)
        if flag_chr & 0x20 != 0:
            pixels[r8(i-840) + 2, 50] = (255,0,0)
            pixels[r8(i-840) + 3, 50] = (255,0,0)
            bm_set(50,r8(i-840) + 2, 1)
            bm_set(50,r8(i-840) + 3, 1)
        if flag_chr & 0x10 != 0:
            pixels[r8(i-672) + 2, 50] = (255,0,0)
            pixels[r8(i-672) + 3, 50] = (255,0,0)
            bm_set(50,r8(i-672) + 2, 1)
            bm_set(50,r8(i-672) + 3, 1)
        if flag_chr & 0x8 != 0:
            pixels[r8(i-504) + 2, 50] = (255,0,0)
            pixels[r8(i-504) + 3, 50] = (255,0,0)
            bm_set(50,r8(i-504) + 2, 1)
            bm_set(50,r8(i-504) + 3, 1)
        if flag_chr & 0x4 != 0:
            pixels[r8(i-336) + 2, 50] = (255,0,0)
            pixels[r8(i-336) + 3, 50] = (255,0,0)
            bm_set(50,r8(i-336) + 2, 1)
            bm_set(50,r8(i-336) + 3, 1)
        if flag_chr & 0x2 != 0:
            pixels[r8(i-168) + 2, 50] = (255,0,0)
            pixels[r8(i-168) + 3, 50] = (255,0,0)
            bm_set(50,r8(i-168) + 2, 1)
            bm_set(50,r8(i-168) + 3, 1)
        if flag_chr & 0x1 != 0:
            pixels[r8(i) + 2, 50] = (255,0,0)
            pixels[r8(i) + 3, 50] = (255,0,0)
            bm_set(50,r8(i) + 2, 1)
            bm_set(50,r8(i) + 3, 1)
        i += 1176
        flag_idx += 1

    pixels[START_Y, START_X] = (0, 255, 0)

    increments = [
        (-1, 0),
        (0, 1),
        (1, 0),
        (0, -1),
    ]

    x = START_X
    y = START_Y
    direction = 0
    iteration = 0

    while x != END_X or y != END_Y:
        v = bm_get(x,y)
        if v:
            direction += 1
        else:
            direction -= 1
        bm_set(x, y, v ^ 1)
        direction %= 4
        increment = increments[direction]
        x += increment[0]
        y += increment[1]

        iteration += 1
        if iteration == iterations:
            break

        try:
            cv = list(pixels[y,x])
            cv[1] = 255
            pixels[y, x] = tuple(cv)
        except IndexError:
            break
    
    img.save("image_" + flag.decode() + "_" + str(iterations) + ".bmp")

def solve():
    print(f"[*] Solving.")

    with open('connectors.txt', 'r') as f:
        all_connectors = f.read().split('\n')
    with open('gates.txt', 'r') as f:
        all_gates = f.read().split('\n')
    with open('fuses.txt', 'r') as f:
        all_fuses = f.read().split('\n')

    states = [[None] * FUSES_Y for _ in range(FUSES_X+1) ]

    for x in range(FUSES_X+1):
        for y in range(FUSES_Y):
            states[x][y] = Bool('x_'+ str(x) + "_" + str(y))

    s = Solver()

    for y in range(FUSES_Y):
        if y % 6 != 4:
            s.add(Not(states[0][y]))

    for x in range(FUSES_X):
        connectors = all_connectors[x]
        gates = all_gates[x]
        fuses = all_fuses[x]

        for y in range(FUSES_Y):
            if fuses[y] == "o":
                if gates[y] == "X":
                    s.add(states[x+1][y] == states[x][y+1])
                elif gates[y] == "x":
                    s.add(states[x+1][y] == states[x][y-1])
                elif gates[y] == "_":
                    s.add(states[x+1][y] == And(states[x][y], states[x][y+1]))
                elif gates[y] == "Y":
                    s.add(states[x+1][y] == states[x][y])
                elif gates[y] == "y":
                    s.add(states[x+1][y] == states[x][y-1])
                elif gates[y] == "j":
                    s.add(states[x+1][y] == states[x][y])
                elif gates[y] == "|":
                    if connectors[y] == "c":
                        s.add(states[x+1][y] == Not(states[x][y]))
                    else:
                        s.add(states[x+1][y])
            else:
                s.add(Not(states[x+1][y]))
    
    s.add(states[FUSES_X][0])
    s.check()
    m = s.model()

    i = 0
    c = 0
    flag = ""
    for y in range(FUSES_Y):
        if y % 6 == 4:
            c *= 2
            if m[states[0][y]]:
                c += 1
            i += 1
            if i == 7:
                flag += chr(c)
                c = 0
                i = 0
    print("[*] Flag:", flag)


with open(sys.argv[1], 'rb') as f:
    data = f.read()
bitmap = bytearray(data[OFFSET:OFFSET+WIDTH * HEIGHT // 8])

# Step 1: parse the fuses, connectors and gates out of the bitmap
parse()

draw("bottom.bmp", HEIGHT - 0x100, HEIGHT, 0, WIDTH)
target_x = 0x235d2
target_y = 0x6a
draw("target.bmp", target_x - 100, target_x + 50, 0, target_y + 50)

# Step 2: simulate some test flags
simulate(b"*" * 25, 1)
simulate(b"*" * 25, -1)
simulate(b"U" * 25, -1)

# Step 3: solve
solve()

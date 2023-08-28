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

import sys
from PIL import Image
from z3 import *
from tqdm import trange

WIDTH = 200
HEIGHT = 300

RED = 0
GREEN = 1
BLUE = 2
ALPHA = 3

CUTOFF_UPPER = 5
CUTOFF_LOWER = 12

FLAG_START_X = 21
FLAG_DELTA_X = 5
NUMBER_FLAG_CHARS = 27

def parse(fn):
    with open(fn, 'r') as f:
        lines = f.read().split('\n')[1:-2]

    nodes = {}

    for line in lines:
        node_number = int(line.split(' ')[0][1:])
        if node_number not in nodes:
            nodes[node_number] = {"label": None, "true": None, "false": None}
        if " -- " not in line:
            label = line.split('"')[1]
            nodes[node_number]["label"] = label
        else:
            other_node_number = int(line.split(' ')[2][1:-1])
            if not nodes[node_number]["true"]:
                nodes[node_number]["true"] = other_node_number
            else:
                nodes[node_number]["false"] = other_node_number
    return nodes

def predict(x, y, c):
    node_number = 0
    while True:
        node = nodes[node_number]
        label = node["label"]

        # According to spec, these can be used out of bounds, but we will error if it does by doing integer arithmetic with a string
        try:
            W = matrix[x-1][y][c]
        except IndexError:
            W = ""
        try:
            N = matrix[x][y-1][c]
        except IndexError:
            N = ""
        try:
            NE = matrix[x+1][y-1][c]
        except IndexError:
            NE = ""
        try:
            WW = matrix[x-2][y][c]
        except IndexError:
            WW = ""

        try:
            NW = matrix[x-1][y-1][c]
        except IndexError:
            NW = ""

        try:
            Prev = matrix[x][y][c-1]
        except IndexError:
            Prev = ""

        if ">" in label:
            prefix = label.split(">")[0]
            other = int(label.split('>')[1])
            if prefix == "c":
                v = c
            elif prefix == "y":
                v = y
            elif prefix == "x":
                v = x
            elif prefix == "W":
                v = W
            elif prefix == "N":
                v = N
            elif prefix == "W-NW":
                v = W-NW
            elif prefix == "ch[-2]":
                v = Prev

            if v > other:
                node_number = node["true"]
            else:
                node_number = node["false"]
        else:
            if '+' in label:
                r = int(label.split('+')[1].split(' ')[0])
                prefix = label.split('+')[0]
            elif '-' in label:
                r = - int(label.split('-')[1].split(' ')[0])
                prefix = label.split('-')[0]

            if prefix == "Zero":
                return 0 + r
            elif prefix == "Top":     
                return N + r
            elif prefix == "TopR":
                return NE + r
            elif prefix == "Left":            
                return W + r
            elif prefix == "LL":            
                return WW + r
            elif prefix == "Avg1": 
                return (W + NW) // 2 + r
            elif prefix == "Grd":
                v = N + W - NW
                # This should be clamped now, but luckily for us (because we'll Z3 later), this is never necessary in our JXL "program".
                # v = max(min(N,W), v)
                # v = min(max(N,W), v)
                return v + r
            
def is_tainted(x, y, c):
    node_number = 0
    while True:
        node = nodes[node_number]
        label = node["label"]

        if ">" in label:
            prefix = label.split(">")[0]
            other = int(label.split('>')[1])
            if prefix == "c":
                v = c
            elif prefix == "y":
                v = y
            elif prefix == "x":
                v = x
            elif prefix == "W":
                return True
            elif prefix == "N":
                return True
            elif prefix == "W-NW":
                return True
            elif prefix == "ch[-2]":
                return True

            if v > other:
                node_number = node["true"]
            else:
                node_number = node["false"]
        else: 
            if '+' in label:
                prefix = label.split('+')[0]
            elif '-' in label:
                prefix = label.split('-')[0]

            if prefix == "Zero":
                return False
            elif prefix == "Top":  
                return True   
            elif prefix == "TopR":
                return True 
            elif prefix == "Left":
                return True             
            elif prefix == "LL":  
                return True           
            elif prefix == "Avg1": 
                return True 
            elif prefix == "Grd":
                return True 

def predict_z3(x, y, c, node_number=0):
    while True:
        node = nodes[node_number]
        label = node["label"]

        # According to spec, these can be used out of bounds, but we will error if it does by doing integer arithmetic with a string
        try:
            W = z3_pixels[x-1][y][c]
        except IndexError:
            W = ""
        try:
            N = z3_pixels[x][y-1][c]
        except IndexError:
            N = ""
        try:
            NE = z3_pixels[x+1][y-1][c]
        except IndexError:
            NE = ""
        try:
            WW = z3_pixels[x-2][y][c]
        except IndexError:
            WW = ""
        try:
            NW = z3_pixels[x-1][y-1][c]
        except IndexError:
            NW = ""
        try:
            Prev = z3_pixels[x][y][c-1]
        except IndexError:
            Prev = ""

        if ">" in label:
            prefix = label.split(">")[0]
            other = int(label.split('>')[1])
            if prefix == "c":
                v = c
            elif prefix == "y":
                v = y
            elif prefix == "x":
                v = x
            elif prefix == "W":
                return If(W > other, predict_z3(x, y, c, node["true"]), predict_z3(x, y, c, node["false"]))
            elif prefix == "N":
                return If(N > other, predict_z3(x, y, c, node["true"]), predict_z3(x, y, c, node["false"]))
            elif prefix == "W-NW":
                return If(W-NW > other, predict_z3(x, y, c, node["true"]), predict_z3(x, y, c, node["false"]))
            elif prefix == "ch[-2]":
                return If(Prev > other, predict_z3(x, y, c, node["true"]), predict_z3(x, y, c, node["false"]))

            if v > other:
                node_number = node["true"]
            else:
                node_number = node["false"]
        else:
            if '+' in label:
                r = int(label.split('+')[1].split(' ')[0])
                prefix = label.split('+')[0]
            elif '-' in label:
                r = - int(label.split('-')[1].split(' ')[0])
                prefix = label.split('-')[0]

            if prefix == "Zero":
                return 0 + r
            elif prefix == "Top":      
                return N + r
            elif prefix == "TopR":
                return NE + r
            elif prefix == "Left":             
                return W + r
            elif prefix == "LL":                
                return WW + r
            elif prefix == "Avg1":
                return (W + NW) / 2 + r
            elif prefix == "Grd":
                v = N + W - NW
                return v + r


fn = sys.argv[1]

print(f"[*] Parsing input file {fn}...")
nodes = parse(fn)

print(f"[*] Generating emulated image for tree {fn}...")

matrix = [[[0 for c in range(4)] for y in range(HEIGHT)] for x in range(WIDTH)]

for y in trange(HEIGHT):
    for x in range(WIDTH):
        for c in range(4):
            matrix[x][y][c] = predict(x,y,c)

img = Image.new(mode = 'RGBA', size = (WIDTH, HEIGHT))
pixels = img.load()

for y in range(HEIGHT):
    for x in range(WIDTH):
        pixels[x,y] = (matrix[x][y][0] // 256, matrix[x][y][1] // 256, matrix[x][y][2] // 256, matrix[x][y][3] // 256)
img.save(fn + "_emulated.png")

print(f"[*] Generating tainted values image for tree {fn}...")

img = Image.new(mode = 'RGBA', size = (WIDTH, HEIGHT))
pixels = img.load()

for y in trange(HEIGHT):
    for x in range(WIDTH):
        pixels[x,y] = (is_tainted(x,y,0) * 255, is_tainted(x,y,3) * 255, 0, 255)
img.save(fn + "_tainted.png")

print(f"[*] Solving with Z3...")

z3_pixels = [[[None for x in range(4)] for y in range(HEIGHT)] for x in range(WIDTH)]

for x in range(WIDTH):
    for y in range(HEIGHT):
        z3_pixels[x][y][RED] = Int(f"x_{x}_{y}")

s = Solver()

for y in range(CUTOFF_UPPER, CUTOFF_LOWER):
    for x in range(WIDTH):
        if x % 5 != 1 and x != 0:
            p = predict_z3(x,y,RED)
            s.add(z3_pixels[x][y][RED] == p)
        else:
            s.add(z3_pixels[x][y][RED] >= 0, z3_pixels[x][y][RED] <= 1)

for y in trange(CUTOFF_LOWER, HEIGHT):
    for x in range(WIDTH):
        p = predict_z3(x,y,RED)
        s.add(z3_pixels[x][y][RED] == p)


# Conditions to show "FLAG GOOD"
s.add(z3_pixels[128][286][RED] == 1)  # originally 0 if "FLAG BAD"

print(f"[*] Checking model... {s.check()}")
m = s.model()

print("[*] Calculating flag...")
flag = ""
for x in range(FLAG_START_X, FLAG_START_X + FLAG_DELTA_X * (NUMBER_FLAG_CHARS + 1), FLAG_DELTA_X):
    c = 0
    for y in range(5, 12):
        c *= 2
        if m[z3_pixels[x][y][RED]].as_long():
            c += 1
    flag += chr(c)

print(f"[*] Flag: {flag}")

print(f"[*] Generating Z3 model visualization...")
img = Image.new(mode = 'RGBA', size = (WIDTH, HEIGHT))
pixels = img.load()

for y in range(HEIGHT):
    for x in range(WIDTH):
        if m[z3_pixels[x][y][RED]] != None:
            v = m[z3_pixels[x][y][RED]].as_long()
            if v != 0:
                pixels[x,y] = (255,0,0,255)
            else:
                pixels[x,y] = (0,255,0,255)
        else:
            pixels[x,y] = (0,0,255,255)
img.save(fn + "_z3.png")

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

import sys
from PIL import Image


imgcache = {}
brdcache = {}
pthcache = {}

SZ = 6
output = []
maxX = 0
maxY = 0
drawops = []
taken = set()
solution_paths = []
input_stuff = []
total = 0

def add_comp(line):
    global maxX, maxY, total
    name, x, y, rot, flip = line.split()
    x, y, rot, flip = int(x), int(y), int(rot), int(flip)
    offsetx = x * SZ
    offsety = y * SZ
    if name not in brdcache:
        lines = open("components/" + name + ".board").readlines()
        header, lines = lines[0], lines[1:]
        W, H = header.split()
        W, H = int(W), int(H)
        brdcache[name] = {"W": W, "H": H, "lines": []}
        for ln in lines:
            ln = ln.strip()
            if not ln: continue
            x,y,w,h,m = [int(c) for c in ln.split()]
            brdcache[name]["lines"].append((x,y,w,h,m))

    if name not in pthcache:
        s = open("components/" + name + ".paths").read()
        paths = s.split("---")
        pthcache[name] = []
        for path in paths:
            path = path.strip()
            if not path: continue
            pthcache[name].append([])
            for line in path.splitlines():
                which, where = line.split()
                pthcache[name][-1].append((which, where))

    if (name,0,0) not in imgcache:
        img = Image.open("components/" + name + ".png")
        for r in range(4):
            for f in range(2):
                new = img.copy()
                if f:
                    new = new.transpose(method = Image.TRANSPOSE)
                for i in range(r):
                    new = new.rotate(270)
                imgcache[(name,r,f)] = new

    maxX = max(maxX, offsetx + brdcache[name]["W"])
    maxY = max(maxY, offsety + brdcache[name]["H"])
    for x in range(brdcache[name]["W"] // SZ):
        for y in range(brdcache[name]["H"] // SZ):
            taken.add((x + offsetx//SZ, y + offsety//SZ))
    drawops.append((32*offsetx//SZ, 32*offsety//SZ, imgcache[name,rot,flip]))

    for path in pthcache[name]:
        solution_paths.append([])
        for line in path:
            which, where = line
            if flip:
                where = {"left":"up", "up":"left", "down":"right", "right":"down"}[where]
            for i in range(rot%4):
                where = {"left":"up", "up":"right", "right":"down", "down":"left"}[where]
            dirx, diry = {"left": (-1,0), "right": (1, 0), "up": (0, -1), "down": (0, 1)}[where]
            solution_paths[-1].append("%d %d %d" % (int(which) + total, dirx, diry))

    for ln in brdcache[name]["lines"]:
        x,y,w,h,m = ln
        if flip:
            x, y = y, x
            w, h = h, w

        for i in range(rot % 4):
            w, h = h, w
            x, y = brdcache[name]["W"] - 1 - y - w + 1, x

        output.append((x+offsetx,y+offsety,w,h,m))
        if m == -1:
            input_stuff.append(total)
        if m != 0:
            total += 1


for line in open(sys.argv[1]).readlines():
    line = line.strip()
    if not line: continue
    add_comp(line)

for x in range(maxX//SZ):
    for y in range(maxY//SZ):
        if (x, y) not in taken:
            add_comp("wall %d %d 0 0" % (x, y))
print(maxX, maxY)
print("\n".join(" ".join(str(c) for c in ln) for ln in output))

if 0:
    img = Image.new("RGB", (maxX // 6 * 32, maxY // 6 * 32))
    for x, y, i in drawops:
        img.paste(i, (x,y))

    img.save("blueprint.png")
open("/tmp/solution", "w").write("\n---\n".join("\n".join(path) for path in solution_paths)
        + "\n---\n" + " ".join(str(i) for i in input_stuff))

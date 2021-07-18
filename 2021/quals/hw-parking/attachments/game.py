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
import time
import string
from PIL import Image, ImageDraw
from matplotlib import pyplot as plt
if sys.platform == 'darwin':
    import matplotlib
    matplotlib.use('TkAgg')
import os

WALL = -1

blocks = []
board = {}


boardfile = open(sys.argv[1]).read()
header, boardfile = boardfile.split("\n", 1)
W, H = [int(x) for x in header.split()]
flagblocks = {}
target = -1
SZ = 4
target_start = None

def putcar(x,y,w,h,m):
    x0 = x*SZ
    x1 = (x+w)*SZ
    y0 = y*SZ
    y1 = (y+h)*SZ
    if m == -1:
        color = (0, 128, 0)
    elif m == -2:
        color = (128, 0, 0)
    else:
        color = (128, 128, 128)

    draw.rectangle((x0+1,y0+1,x1-2,y1-2), fill=color)

def putwall(x,y,w,h):
    x0 = x*SZ
    x1 = (x+w)*SZ
    y0 = y*SZ
    y1 = (y+h)*SZ
    draw.rectangle((x0,y0,x1-1,y1-1), fill=(48,24,0))



walls = []
for line in boardfile.splitlines():
    if not line.strip(): continue
    x,y,w,h,movable = [int(x) for x in line.split()]

    if movable == -1:
        flagblocks[len(blocks)] = (x,y)
    elif movable == -2:
        target = len(blocks)
        target_start = x, y

    for i in range(x, x+w):
        for j in range(y, y+h):
            if movable != 0:
                if (i,j) in board:
                    print("Car overlap at %d, %d" % (i,j))
                    #assert False
                board[(i,j)] = len(blocks)
            else:
                if (i,j) in board and board[i,j] != WALL:
                    print("Wall-car overlap at %d, %d" % (i,j))
                    #assert False
                board[(i,j)] = WALL
    if movable:
        blocks.append([x,y,w,h, movable])
    else:
        walls.append([x,y,w,h])

def printflag():
    if os.environ.get("FLAG") == "0":
        print("<flag would be here if on real level>")
        return
    bits = ""
    for fl in flagblocks:
        orig_xy = flagblocks[fl]
        new_xy = tuple(blocks[fl][:2])
        bit = 0 if orig_xy == new_xy else 1
        bits += str(bit)

    flag = b"CTF{"
    while bits:
        byte, bits = bits[:8], bits[8:]
        flag += bytes([ int(byte[::-1], 2) ])
    flag += b"}"

    print(flag)

def check_win():
    x, y = blocks[target][:2]
    if target_start is not None and target_start != (x,y):
        print("Congratulations, here's your flag:")
        printflag()
        sys.exit(0)

print("Here's the parking. Can you move the red car?")
print("Green cars' final position will encode the flag.")
print("Move by clicking a car, then clicking a near empty space to move to. Feel free to zoom in using the magnifying glass if necessary!")
#print_board()

def can_move(which, dirx, diry):
    x,y,w,h,mv = blocks[which]
    if w == 1 and dirx != 0:
        print("This car moves only vertically...")
        return False
    if h == 1 and diry != 0:
        print("This car only moves horizontally...")
        return False
    bad = False
    for i in range(x+dirx, x+dirx+w):
        for j in range(y+diry, y+diry+h):
            if (i,j) in board and board[(i,j)] != which:
                bad = True
    if bad:
        print("Such a move would cause collision...")
        return False
    return True

def do_move(which, dirx, diry):
    x,y,w,h,mv = blocks[which]
    for i in range(x, x+w):
        for j in range(y, y+h):
            del board[(i,j)]
    x += dirx
    y += diry
    blocks[which] = [x, y, w, h, mv]
    for i in range(x, x+w):
        for j in range(y, y+h):
            board[(i,j)] = which
    if mv == -1:
        print("This setting corresponds to the following flag:")
        printflag()

def onclick(event):
    global which
    global xy
    if which is None:
        x, y = event.xdata, event.ydata
        x, y = int(x), int(y)
        xy = (x, y)
        try:
            which = board[x//SZ, y//SZ]
            if which == WALL:
                which = None
                print("Selected wall...")
                return
            print("Car %d selected." % which)
        except KeyError:
            print("Selected empty space...")
            which = None
        return

    dirx, diry = event.xdata - xy[0], event.ydata - xy[1]
    if abs(dirx) > abs(diry):
        dirx, diry = (1, 0) if dirx > 0 else (-1, 0)
    else:
        dirx, diry = (0, 1) if diry > 0 else (0, -1)

    if not can_move(which, dirx, diry):
        which = None
        return

    do_move(which, dirx, diry)
    which = None
    redraw()
    check_win()
    

DRAW = True
if os.environ.get("DRAW") == "0":
    DRAW = False

first = True
def redraw():
    print("Redrawing...")
    global draw, first, ax
    im = Image.new("RGB", (W*SZ,H*SZ), (255,255,255))
    draw = ImageDraw.Draw(im)
    for wall in walls:
        putwall(*wall)
    for block in blocks:
        putcar(*block)
    print("Redrawn.")
    if first:
        print("Saving...")
        im.save("initial.png")
        print("Saved.")
        first = False
        ax = fig.add_subplot(111)
        ax = ax.imshow(im)
    ax.set_data(im)

    plt.draw()

if DRAW:
    fig = plt.figure()
    plt.ion()
    plt.show()
    cid = fig.canvas.mpl_connect('button_press_event', onclick)
    redraw()

which = None
xy = None

# Alternative API, you don't have to click ;)
while True:
    i = input()
    which, dirx, diry = i.strip().split()
    which, dirx, diry = int(which), int(dirx), int(diry)
    if can_move(which, dirx, diry):
        do_move(which, dirx, diry)
        print("Moved")
        if DRAW:
            redraw()
        check_win()
    else:
        print("Invalid")

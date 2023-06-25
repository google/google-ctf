#!/usr/bin/python3

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

import turtle
from sys import stdin
from PIL import Image

def hexToRgb(hx):
  return (int(hx[1:3], 16), int(hx[3:5], 16), int(hx[5:7], 16))

# Get the canvas color at |turt|'s position.
def getColor(turt):
  x = int(turt.pos()[0])
  y = -int(turt.pos()[1])
  canvas = turtle.getcanvas()
  ids = canvas.find_overlapping(x, y, x, y)
  for index in ids[::-1]:
    color = canvas.itemcget(index, "fill")
    if color and color[0] == "#":
      return hexToRgb(color)
  return (255, 255, 255)

# Draw the image file from |path| with |turt|
def drawImg(path, turt):
  im = Image.open(path).convert("RGB")
  w, h = im.size
  px = im.load()
  turt.pendown()
  for yy in range(h):
    for xx in range(w):
      turt.pencolor(px[xx, yy])
      turt.forward(5)
    turt.penup()
    turt.back(w*5)
    turt.right(90)
    turt.forward(5)
    turt.left(90)
    turt.pendown()
  turt.penup()
  turt.left(90)
  turt.forward(h*5)
  turt.right(90)

mTurt = None
def loadM(flag):
  global mTurt
  mTurt = turtle.Turtle()
  mTurt.speed(0)
  mTurt.pensize(5)
  mTurt.penup()
  mTurt.forward(12*5)
  drawImg("m.png", mTurt)
  mTurt.pendown()
  for i in range(len(flag)):
    mTurt.pencolor((ord(flag[i]), 0, 0))
    mTurt.forward(5)
    if i == 24:
      mTurt.penup()
      mTurt.back(25*5)
      mTurt.right(90)
      mTurt.forward(5)
      mTurt.left(90)
      mTurt.pendown()
  mTurt.penup()
  mTurt.back(10*5)
  mTurt.left(90)
  mTurt.forward(5)
  mTurt.right(90)

def readM(a):
  mTurt.forward((a%25)*5)
  mTurt.right(90)
  mTurt.forward((a//25)*5)
  c = getColor(mTurt)
  mTurt.right(90)
  mTurt.forward((a%25)*5)
  mTurt.right(90)
  mTurt.forward((a//25)*5)
  mTurt.right(90)
  return c

def writeM(a, c):
  mTurt.right(90)
  mTurt.forward((a//25)*5)
  mTurt.left(90)
  mTurt.forward((a%25)*5)
  mTurt.pencolor(c)
  mTurt.pendown()
  mTurt.forward(0)
  mTurt.penup()
  mTurt.left(90)
  mTurt.forward((a//25)*5)
  mTurt.left(90)
  mTurt.forward((a%25)*5)
  mTurt.left(180)

sTurt = None
def loadS():
  global sTurt
  sTurt = turtle.Turtle()
  sTurt.speed(0)
  sTurt.pensize(5)
  sTurt.penup()
  sTurt.left(90)
  sTurt.forward(50*5)
  sTurt.left(90)
  sTurt.forward(4*5)
  sTurt.left(90)
  sTurt.pencolor((255, 128, 128))
  sTurt.pendown()
  sTurt.forward(120*5)
  sTurt.penup()

def readS(a):
  sTurt.forward(a*5)
  c = getColor(sTurt)
  sTurt.back(a*5)
  return c

def writeS(a, c):
  sTurt.forward(a*5)
  sTurt.pencolor(c)
  sTurt.pendown()
  sTurt.forward(0)
  sTurt.penup()
  sTurt.back(a*5)

rTurt = None
def loadR():
  global rTurt
  rTurt = turtle.Turtle()
  rTurt.speed(0)
  rTurt.pensize(5)
  rTurt.penup()
  rTurt.forward(20*5)
  rTurt.left(90)
  rTurt.forward(40*5)
  rTurt.right(90)
  sTurt.pencolor((0, 0, 0))
  for i in range(3):
    for j in range(3):
      rTurt.pendown()
      rTurt.forward(0)
      rTurt.penup()
      rTurt.forward(2*5)
    rTurt.back(6*5)
    rTurt.right(90)
    rTurt.forward(2*5)
    rTurt.left(90)
  rTurt.left(90)
  rTurt.forward(6*5)
  rTurt.right(90)

def readR(n):
  rTurt.forward((n%3)*10)
  rTurt.right(90)
  rTurt.forward((n//3)*10)
  c = getColor(rTurt)
  rTurt.right(90)
  rTurt.forward((n%3)*10)
  rTurt.right(90)
  rTurt.forward((n//3)*10)
  rTurt.right(90)
  return c

def writeR(n, c):
  rTurt.forward((n%3)*10)
  rTurt.right(90)
  rTurt.forward((n//3)*10)
  rTurt.pencolor(c)
  rTurt.pendown()
  rTurt.forward(0)
  rTurt.penup()
  rTurt.right(90)
  rTurt.forward((n%3)*10)
  rTurt.right(90)
  rTurt.forward((n//3)*10)
  rTurt.right(90)

cTurt = None
def loadC():
  global cTurt
  cTurt = turtle.Turtle()
  cTurt.speed(0)
  cTurt.pensize(5)
  cTurt.penup()
  cTurt.left(90)
  cTurt.forward(50*5)
  cTurt.right(90)
  drawImg("c.png", cTurt)

def getRNum(colorOrInt):
  if type(colorOrInt) == tuple:
    colorOrInt = colorOrInt[0]
  return (colorOrInt-20) // 40

def read(op, isR, isP, isC):
  if isP:
    return readPVal(op, isR, isC)
  elif isR:
    return readRVal(getRNum(op))
  elif isC:
    return readC(op)
  raise BaseException("invalid insn")

def readRVal(rNum):
  return readC(readR(rNum))

def write(op, val, isR, isP, isC):
  if isP:
    writePVal(op, val, isR, isC)
  elif isR:
    writeRVal(getRNum(op), val)
  else:
    raise BaseException("invalid insn")

def writeRVal(rNum, val):
  writeR(rNum, cToColor(val))

def writePVal(op, val, isS, isC):
  a = readPA(op, isC)
  if isS:
    writeS(a, cToColor(val))
  else:
    writeM(a, cToColor(val))

def readPVal(op, isS, isC):
  a = readPA(op, isC)
  if isS:
    return readC(readS(a))
  else:
    return readC(readM(a))

def readPA(op, isC):
  if isC:
    return readC(op)
  a = 0
  if op[0] != 0:
    a = readRVal(getRNum(op[0]))
  if op[1] != 0:
    a += readRVal(getRNum(op[1]))
  a += readOneByteC(op[2])
  return a

def readC(op):
  c = op[0] + (op[1]<<8) + (op[2]<<16)
  if c >= (256**3)//2:
    c = -((256**3)-c)
  return c

def readOneByteC(val):
  if val > 256//2:
    return -(256-val)
  return val

def cToColor(val):
  if val < 0:
    val = 256**3 + val
  return [val%256, (val>>8)%256, (val>>16)%256]

def run():
  while True:
    color0 = getColor(cTurt)
    cmpcolor = (color0[0]&0xfc, color0[1]&0xfc, color0[2]&0xfc)
    cTurt.forward(5)
    color1 = getColor(cTurt)
    cTurt.forward(5)
    color2 = getColor(cTurt)
    cTurt.back(2*5)
    isR1 = color0[0]&1 != 0
    isP1 = color0[1]&1 != 0
    isC1 = color0[2]&1 != 0
    isR2 = color0[0]&2 != 0
    isP2 = color0[1]&2 != 0
    isC2 = color0[2]&2 != 0
    if cmpcolor == (0,252,0):
      print("correct flag!")
      exit(0)
    elif cmpcolor == (252,0,0):
      print("wrong flag :C")
      exit(0)
    elif cmpcolor == (204, 204, 252):
      sTurt.forward(readC(color1)*5)
    elif cmpcolor == (220, 252, 0) or cmpcolor == (252, 188, 0) or cmpcolor == (64, 224, 208) or cmpcolor == (156, 224, 188) or cmpcolor == (100, 148, 236) or cmpcolor == (252, 124, 80):
      if cmpcolor == (252, 188, 0):
        val2 = readPA(color2, isC2)
      else:
        val2 = read(color2, isR2, isP2, isC2)

      if cmpcolor == (220, 252, 0) or cmpcolor == (252, 188, 0):
        write(color1, val2, isR1, isP1, isC1)
      elif cmpcolor == (64, 224, 208):
        val1 = read(color1, isR1, isP1, isC1)
        write(color1, val1+val2, isR1, isP1, isC1)
      elif cmpcolor == (156, 224, 188):
        val1 = read(color1, isR1, isP1, isC1)
        write(color1, val1-val2, isR1, isP1, isC1)
      elif cmpcolor == (100, 148, 236):
        val1 = read(color1, isR1, isP1, isC1)
        write(color1, val1>>val2, isR1, isP1, isC1)
      elif cmpcolor == (252, 124, 80):
        val1 = read(color1, isR1, isP1, isC1)
        writeRVal(6, 16581630 if (val1 == val2) else 0)
        writeRVal(7, 16581630 if (val1 < val2) else 0)
        writeRVal(8, 16581630 if (val1 > val2) else 0)
    elif cmpcolor == (220, 48, 96):
      e = readRVal(6)
      l = readRVal(7)
      g = readRVal(8)
      if (color0[0]&1 != 0 and e) or (color0[1]&1 != 0 and not e) or (color0[0]&2 != 0 and l) or (color0[1]&2 != 0 and g):
        cTurt.right(90)
        cTurt.forward((readC(color1)-1)*5)
        cTurt.left(90)
    elif cmpcolor == (252, 0, 252):
      sTurt.back(5)
      writeS(0, (color1[0], color1[1], 127))
      cTurt.forward(color1[0]*5)
      cTurt.left(90)
      cTurt.forward((color1[1]+1)*5)
      cTurt.right(90)
    elif cmpcolor == (128, 0, 128):
      cTurt.left(90)
      cTurt.forward(readC(color1)*5)
      cTurt.left(90)
      cTurt.forward(readS(0)[0]*5)
      cTurt.left(90)
      cTurt.forward(readS(0)[1]*5)
      cTurt.left(90)
      sTurt.forward(5)
    else:
      raise BaseException("unknown: %s" % str(cmpcolor))
    cTurt.right(90)
    cTurt.forward(5)
    cTurt.left(90)

flag = input("Flag: ")
if len(flag) != 35:
  print("Wrong len :(")
  exit(0)

turtle.Screen().colormode(255)

loadM(flag)
loadS()
loadR()
loadC()
run()

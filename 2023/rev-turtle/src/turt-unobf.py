# python3 logo.py

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

OP_SUCCESS = (0,252,0)
OP_FAIL = (252,0,0)
OP_MOV = (220, 252, 0)
OP_LEA = (252, 188, 0)
OP_SUB = (156, 224, 188)
OP_ADD = (64, 224, 208)
OP_SHR = (100, 148, 236)
OP_CMP = (252, 124, 80)
OP_J = (220, 48, 96)
OP_CALL = (252, 0, 252)
OP_RET = (128, 0, 128)
OP_INC_SP = (204, 204, 252)

def hexToRgb(hx):
  return (int(hx[1:3], 16), int(hx[3:5], 16), int(hx[5:7], 16))

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

def getReg(reg):
  if type(reg) == tuple:
    reg = reg[0]
  return (reg-20) // 40

def read(op, isReg, isPtr, isConst):
  if isPtr:
    return readPtrVal(op, isReg, isConst)
  elif isReg:
    return readRegVal(getReg(op))
  elif isConst:
    return readConst(op)
  raise BaseException("invalid instruction")

def readRegVal(regNum):
  return readConst(readR(regNum))

def write(op, val, isReg, isPtr, isConst):
  if isPtr:
    writePtrVal(op, val, isReg, isConst)
  elif isReg:
    writeRegVal(getReg(op), val)
  else:
    raise BaseException("invalid instruction")

def writeRegVal(regNum, val):
  writeR(regNum, constToPx(val))

def writePtrVal(op, val, isStack, isConst):
  addr = readPtrAddr(op, isConst)
  if isStack:
    writeS(addr, constToPx(val))
  else:
    writeM(addr, constToPx(val))

def readPtrVal(op, isStack, isConst):
  addr = readPtrAddr(op, isConst)
  if isStack:
    return readConst(readS(addr))
  else:
    return readConst(readM(addr))

def readPtrAddr(op, isConst):
  if isConst:
    return readConst(op)
  addr = 0
  if op[0] != 0:
    addr = readRegVal(getReg(op[0]))
  if op[1] != 0:
    addr += readRegVal(getReg(op[1]))
  addr += readOneByteConst(op[2])
  return addr

def readConst(op):
  const = op[0] + (op[1]<<8) + (op[2]<<16)
  if const >= (256**3)//2:
    const = -((256**3)-const)
  return const

def readOneByteConst(val):
  if val > 256//2:
    return -(256-val)
  return val

def constToPx(val):
  if val < 0:
    val = 256**3 + val
  return [val%256, (val>>8)%256, (val>>16)%256]

def run():
  global cTurt
  global sp
  global stack
  while True:
    opcode = getColor(cTurt)
    cmpcode = (opcode[0]&0xfc, opcode[1]&0xfc, opcode[2]&0xfc)
    cTurt.forward(5)
    op1 = getColor(cTurt)
    cTurt.forward(5)
    op2 = getColor(cTurt)
    cTurt.back(2*5)
    isReg1 = opcode[0]&1 != 0
    isPtr1 = opcode[1]&1 != 0
    isConst1 = opcode[2]&1 != 0
    if cmpcode == OP_SUCCESS:
      print("correct flag!")
      exit(0)
    elif cmpcode == OP_FAIL:
      print("wrong flag :C")
      exit(0)
    elif cmpcode == OP_INC_SP:
      amount = readConst(op1)
      sTurt.forward(readConst(op1)*5)
    elif cmpcode == OP_MOV or cmpcode == OP_LEA or cmpcode == OP_ADD or cmpcode == OP_SUB or cmpcode == OP_SHR or cmpcode == OP_CMP:
      if cmpcode == OP_LEA:
        val2 = readPtrAddr(op2, opcode[2]&2 != 0)
      else:
        val2 = read(op2, opcode[0]&2 != 0, opcode[1]&2 != 0, opcode[2]&2 != 0)

      if cmpcode == OP_MOV or cmpcode == OP_LEA:
        write(op1, val2, isReg1, isPtr1, isConst1)
      elif cmpcode == OP_ADD:
        val1 = read(op1, isReg1, isPtr1, isConst1)
        write(op1, val1+val2, isReg1, isPtr1, isConst1)
      elif cmpcode == OP_SUB:
        val1 = read(op1, isReg1, isPtr1, isConst1)
        write(op1, val1-val2, isReg1, isPtr1, isConst1)
      elif cmpcode == OP_SHR:
        val1 = read(op1, isReg1, isPtr1, isConst1)
        write(op1, val1>>val2, isReg1, isPtr1, isConst1)
      elif cmpcode == OP_CMP:
        val1 = read(op1, isReg1, isPtr1, isConst1)
        writeRegVal(6, 16581630 if (val1 == val2) else 0)
        writeRegVal(7, 16581630 if (val1 < val2) else 0)
        writeRegVal(8, 16581630 if (val1 > val2) else 0)
    elif cmpcode == OP_J:
      e = readRegVal(6)
      l = readRegVal(7)
      g = readRegVal(8)
      if (opcode[0]&1 != 0 and e) or (opcode[1]&1 != 0 and not e) or (opcode[0]&2 != 0 and l) or (opcode[1]&2 != 0 and g):
        cTurt.right(90)
        cTurt.forward((readConst(op1)-1)*5)
        cTurt.left(90)
    elif cmpcode == OP_CALL:
      sTurt.back(5)
      writeS(0, (op1[0], op1[1], 127))
      cTurt.forward(op1[0]*5)
      cTurt.left(90)
      cTurt.forward((op1[1]+1)*5)
      cTurt.right(90)
    elif cmpcode == OP_RET:
      cTurt.left(90)
      cTurt.forward(readConst(op1)*5)
      cTurt.left(90)
      cTurt.forward(readS(0)[0]*5)
      cTurt.left(90)
      cTurt.forward(readS(0)[1]*5)
      cTurt.left(90)
      sTurt.forward(5)
    else:
      raise BaseException("unknown op: %s" % str(cmpcode))
    cTurt.right(90)
    cTurt.forward(5)
    cTurt.left(90)

flag = "CTF{iT5_E-tUr+1es/AlL.7h3;waY:d0Wn}" # input("Flag: ")
if len(flag) != 35:
  print("Wrong len :(")
  exit(0)

turtle.Screen().colormode(255)

loadM(flag)
loadS()
loadR()
loadC()
run()

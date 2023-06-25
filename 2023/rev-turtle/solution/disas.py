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

im = Image.open("c.png")
pix = im.load()
w, h = im.size

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
    return "reg_%d" % rNum

def readPVal(op, isS, isC):
  a = readPA(op, isC)
  if isS:
      return "STACK[%s]" % a
  else:
      return "MEM[%s]" % a

def readPA(op, isC):
  if isC:
    return "%d" % readC(op)
  aa = []
  if op[0] != 0:
    aa.append(readRVal(getRNum(op[0])))
  if op[1] != 0:
    aa.append("%s" % readRVal(getRNum(op[1])))
  c = readOneByteC(op[2])
  if c != 0:
      aa.append("%d" % c)
  return "+".join(aa)

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

def getat(x, y):
    color0 = pix[x, y]
    color1 = pix[x+1, y]
    color2 = pix[x+2, y]
    isR1,isP1,isC1 = color0[0]&1, color0[1]&1, color0[2]&1
    isR2,isP2,isC2 = color0[0]&2, color0[1]&2, color0[2]&2
    cmpcolor = (color0[0]&0xfc, color0[1]&0xfc, color0[2]&0xfc)
    if cmpcolor == (0,252,0):
        disassembled = "WIN"
    elif cmpcolor == (252,0,0):
        disassembled = "LOSE"
    elif cmpcolor == (204, 204, 252):
        disassembled = "DROP %d VALUES" % readC(color1)
    elif cmpcolor == (220, 252, 0) or cmpcolor == (252, 188, 0) or cmpcolor == (64, 224, 208) or cmpcolor == (156, 224, 188) or cmpcolor == (100, 148, 236) or cmpcolor == (252, 124, 80):
      val1 = read(color1, isR1, isP1, isC1)
      if cmpcolor == (252, 188, 0):
        val2 = readPA(color2, isC2)
      else:
        val2 = read(color2, isR2, isP2, isC2)

      if cmpcolor == (220, 252, 0) or cmpcolor == (252, 188, 0):
        disassembled = "MOV"
      elif cmpcolor == (64, 224, 208):
        disassembled = "ADD"
      elif cmpcolor == (156, 224, 188):
        disassembled = "SUB"
      elif cmpcolor == (100, 148, 236):
        disassembled = "SHR"
      elif cmpcolor == (252, 124, 80):
        disassembled = "CMP"
      disassembled += " %s, %s" % (read(color1, isR1, isP1, isC1), val2)
    elif cmpcolor == (220, 48, 96):
        conds = []
        if color0[0]&1 != 0:
            conds.append("==")
        if color0[1]&1 != 0:
            conds.append("!=")
        if color0[0]&2 != 0:
            conds.append("<")
        if color0[1]&2 != 0:
            conds.append(">")
        if len(conds) == 4:
            disassembled = "JUMP BY %d" % (readC(color1))
        else:
            disassembled = "JUMP BY %d IF %s" % (readC(color1), ",".join(conds))
    elif cmpcolor == (252, 0, 252):
        right = color1[0]
        up = color1[1]
        disassembled = "CALL RIGHT %d UP %d" % (right, up)
    elif cmpcolor == (128, 0, 128):
        up = readC(color1)
        disassembled = "RETURN THISFUN %d" % up
    elif color0 == (255, 255, 255):
        disassembled = "NOP" # Not really, but...
    else:
        disassembled = "<unknown>"
    
    return disassembled

for j in range(h):
    s = "%02d: " % j
    for i in range(0, w, 3):
        x = getat(i, j)
        s += "%30s " % x
    print(s)

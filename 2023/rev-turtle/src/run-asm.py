# python3 run-asm.py

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
from numpy import asarray

flag = "CTF{iT5_E-tUr+1es/AlL.7h3;waY:d0Wn}"

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

code = None
sp = None
stack = None
regs = None
memory = None

def initMemory(flag):
  global sp
  global stack
  global regs
  global memory

  sp = 500
  stack = [(0,0,0) for i in range(500)]
  regs = [(0,0,0) for i in range(9)]
  flag = [ord(c) for c in flag]
  if len(flag) != 35:
    raise BaseException("wrong len for flag: %d" % len(flag))
  sFlag = [0 for i in range(30)]
  sortArr = [23,14,7,18,12,1,28,15,26,0,5,21,27,3,11,24,13,2,8,22,6,10,29,19,17,9,20,4,16,25]
  if len(sortArr) != 30:
    raise BaseException("wrong len for sortArr: %d" % len(sortArr))
  cmpArr = [1,1,1,3,1,1,1,2,1,4,1,1,1,2,3,1,1,3,1,1,2,1,3,1,1,2,3,1,1,2,2,3,1,1,2,2,2,4,1,3,1,2,1,1,1,4,1,2,1,1,3,1,2,1,1,2,4,1,2,1,3,1,2,1,2,1,4,1,2,1,2,1,4,1,2,1,2,3,1,2,3,1,2,2,1,1,4,1,2,2,1,1,4,1,2,2,1,1,4,1,2,2,1,1,4,1,2,2,1,1,4,1,2,2,1,3,1,2,2,1,2,4,1,2,2,1,2,4,1,2,2,1,2,4,1,2,2,3,1,2,2,2,1,4,1,2,2,2,1,4,1,2,2,2,1,4,1,2,2,2,1,4,1,2,2,2,1,4,1,2,2,2,1,4,1,2,2,2,3,1,2,2,2,2,4,1,2,2,2,2,4,1,2,2,2,2,4,1,2,2,2,2,4,1,2,2,2,2,4,1,2,2,2,2,4,1,2,2,2,2,4,3,2,1,1,1,3,2,1,1,1,2,4,2,1,1,3,2,1,1,2,1,4,2,1,1,2,3,2,1,1,2,2,4,2,1,1,2,2,4,2,1,1,2,2,4,2,1,1,2,2,4,2,1,1,2,2,4,2,1,3,2,1,2,1,1,4,2,1,2,1,3,2,1,2,1,2,4,2,1,2,1,2,4,2,1,2,3,2,1,2,2,3,2,1,2,2,2,4,2,1,2,2,2,4,2,3,2,2,1,1,3,2,2,1,1,2,4,2,2,1,1,2,4,2,2,1,3,2,2,1,2,1,4,2,2,1,2,3,2,2,1,2,2,4,2,2,1,2,2,4,2,2,1,2,2,4,2,2,3,2,2,2,1,3,2,2,2,3,2,2,2,2,1,4,2,2,2,2,1,4,2,2,2,2,3,2,2,2,2,2,4,2,2,2,2,2,4,2,2,2,2,2,4]
  if len(cmpArr) != 424:
    raise BaseException("wrong len for cmpArr: %d" % len(cmpArr))
  cmpPos = [0]
  memory = [(i, 0, 0) for i in flag+sFlag+sortArr+cmpArr+cmpPos]

def getReg(reg):
  if type(reg) == tuple:
    reg = reg[0]
  return (reg-20) // 40

def getRegStr(num):
  return ["si", "di", "a", "b", "c", "d", "equal", "less", "greater"][num]

def read(op, isReg, isPtr, isConst):
  if isPtr:
    return readPtrVal(op, isReg, isConst)
  elif isReg:
    return readRegVal(getReg(op))
  elif isConst:
    return readConst(op)
  raise BaseException("invalid instruction")

def readRegVal(regNum):
  # print("read", getRegStr(regNum), ":", readConst(regs[regNum]))
  return readConst(regs[regNum])

def write(op, val, isReg, isPtr, isConst):
  if isPtr:
    writePtrVal(op, val, isReg, isConst)
  elif isReg:
    writeRegVal(getReg(op), val)
  else:
    raise BaseException("invalid instruction")

def writeRegVal(regNum, val):
  # print("write", getRegStr(regNum), ":", val)
  regs[regNum] = constToPx(val)

def writePtrVal(op, val, isStack, isConst):
  global memory
  addr = readPtrAddr(op, isConst)
  if isStack:
    stack[sp+addr] = constToPx(val)
    # print("write stack[%d] = %d" % (addr, val))
  else:
    memory[addr] = constToPx(val)
    # print("write memory[%d] = %d" % (addr, val))

def readPtrVal(op, isStack, isConst):
  addr = readPtrAddr(op, isConst)
  if isStack:
    # print("read stack[%d]: %d" % (addr, readConst(stack[addr])))
    return readConst(stack[sp+addr])
  else:
    # print("read memory[%d]: %d" % (addr, readConst(memory[addr])))
    return readConst(memory[addr])

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
  # Little endian
  const = op[0] + (op[1]<<8) + (op[2]<<16)
  # Twos complement on 3 bytes
  if const >= (256**3)//2:
    const = -((256**3)-const)
  return const

def readOneByteConst(val):
  if val > 256//2:
    return -(256-val)
  return val

def constToPx(val):
  # Twos complement on 3 bytes
  if val < 0:
    val = 256**3 + val
  # Little endian
  return [val%256, (val>>8)%256, (val>>16)%256]

def execCode():
  global code
  global sp
  global stack
  pcx = pcy = 0
  while True:
    opcode = code[pcy][pcx]
    cmpcode = (opcode[0]&0xfc, opcode[1]&0xfc, opcode[2]&0xfc)
    op1 = code[pcy][pcx+1]
    op1 = (op1[0], op1[1], op1[2])
    op2 = code[pcy][pcx+2]
    op2 = (op2[0], op2[1], op2[2])
    isReg1 = opcode[0]&1 != 0
    isPtr1 = opcode[1]&1 != 0
    isConst1 = opcode[2]&1 != 0
    if cmpcode == OP_SUCCESS:
      print("correct flag!")
      break
    elif cmpcode == OP_FAIL:
      print("wrong flag :C")
      break
    elif cmpcode == OP_INC_SP:
      amount = readConst(op1)
      # print(pcx, pcy, "inc-sp %d" % amount)
      sp += amount
    elif cmpcode == OP_MOV or cmpcode == OP_LEA or cmpcode == OP_ADD or cmpcode == OP_SUB or cmpcode == OP_SHR or cmpcode == OP_CMP:
      for c, p in [(OP_MOV, "mov"), (OP_LEA, "lea"), (OP_ADD, "add"), (OP_SUB, "sub"), (OP_SHR, "shr"), (OP_CMP, "cmp")]:
        if c == cmpcode:
          # print(pcx, pcy, p)
          break
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
        # print("%d ? %d" % (val1, val2))
        writeRegVal(6, 1 if (val1 == val2) else 0) # equal flag
        writeRegVal(7, 1 if (val1 < val2) else 0)  # less flag
        writeRegVal(8, 1 if (val1 > val2) else 0)  # greater flag
    elif cmpcode == OP_J:
      # print(pcx, pcy, "jump")
      e = readRegVal(6)
      l = readRegVal(7)
      g = readRegVal(8)
      if (opcode[0]&1 != 0 and e) or (opcode[1]&1 != 0 and not e) or (opcode[0]&2 != 0 and l) or (opcode[1]&2 != 0 and g):
        # print("jumped %d" % readConst(op1))
        pcy += readConst(op1)-1
    elif cmpcode == OP_CALL:
      # print(pcx, pcy, "call", op1[0], op1[1])
      sp -= 1
      stack[sp] = (op1[0], op1[1], 127)
      pcx += op1[0]
      pcy -= op1[1]+1
    elif cmpcode == OP_RET:
      pcy -= readConst(op1)
      pcx -= stack[sp][0]
      pcy += stack[sp][1]
      sp += 1
      # print(pcx, pcy, "ret", pcx, pcy)
    else:
      raise BaseException("unknown op: %s" % str(cmpcode))
    pcy += 1
    # if pcx == 6:
    #   print([m[0] for m in memory[35:65]]) # sFlag
    #   # +-./01357:;AELTUWY_adehilnrstw
    #   # iT5_E-tUr+1es/AlL.7h3;waY:d0Wn
    #   raise BaseException("break")

image = Image.open('c.png')
code = asarray(image) # y, x, rgb
h, w, _ = code.shape
print(w, h)
try:
  initMemory(flag)
  execCode()
  # for i in range(len(flag)):
  #   for cc in range(256):
  #     if flag[i] == chr(cc):
  #       continue;
  #     tmp = flag[i]
  #     modFlag = flag[:i] + chr(cc) + flag[i+1:]
  #     for j in range(len(flag)):
  #       if i == j:
  #         continue
  #       if modFlag[j] == chr(cc):
  #         modFlag = modFlag[:j] + tmp + modFlag[j+1:]
  #         break
  #     initMemory(modFlag)
  #     execCode()
except BaseException as e:
  print(e)
  # raise e


# TODO: replace op with somethin (e.g. color)

# python3 export-asm.py

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

import re
from PIL import Image
import numpy as np


funs = ["crackme", "genSortedFlag", "binsearch"]
data = [
  ["sflag", 16528, 35], # Len: 30
  ["flag", 16480, 0], # Len: 35
  ["sortArr", 8240, 65], # Len: 30. Should init to {...}
  ["cmpArr", 8288, 95], # Len: 424. Should init to {...}
  ["cmpPos", 16448, 519], # Len: 1. Should init to 0
]

opcodes = {
  "success": (0,252,0), "fail": (252,0,0),
  "mov": (220, 252, 0), "lea": (252, 188, 0),
  "sub": (156, 224, 188), "add": (64, 224, 208), "shr": (100, 148, 236),
  "cmp": (252, 124 , 80), "j": (220, 48, 96),
  "call": (252, 0, 252), "ret": (128, 0, 128), "inc-sp": (204, 204, 252),
}
for n, c in opcodes.items():
  for cc in c:
    if cc%4 != 0:
      print("code not valid:", c)
      exit(0)

regs = ["bp", "sp", "si", "di", "a", "b", "c", "d"]
regNums = {}
for i in range(len(regs[2:])): # sp, bp not present in output opcodes
  regNums[regs[i+2]] = 20+i*40

def getOps(ops):
  op1, op2 = ops.split(",")
  if "#" in op2 and "<" in op2 and "PTR" in op1:
    end = op2.split("#")[1]
    op2 = op2.split("#")[0]
    op1 += " #" + end
  return op1.strip(), op2.strip()

def getReg(s):
  if s == "rbp":
    return "bp"
  elif s == "rsp":
    return "sp"
  elif s == "esi" or s == "rsi":
    return "si"
  elif s == "edi" or s == "rdi":
    return "di"
  else:
    for r in ['a', 'b', 'c', 'd']:
      if s == "r"+r+"x" or s == "e"+r+"x" or s == r+"l":
        return r
  raise BaseException("unknown reg: %s" % s)

def isReg(s):
  try:
    getReg(s)
  except:
    return False
  return True

def getMem(s):
  return ["m", int(s.split("#")[1].strip().split(" ")[0].strip(), 16), s.split("<")[1].split(">")[0].strip()]

def isMem(s):
  return "#" in s and "<" in s

def getPtr(s):
  offs = s.split("[")[1].split("]")[0]
  if "-" in offs:
    r, o = offs.split("-")
  elif "+" in offs:
    r, o = offs.split("+")
  else:
    return ["r", getReg(offs)]
  try:
    o = int(o[2:], 16)
  except:
    # [rax+rcx*1], [rax+rax*1+0x0]
    if o.endswith("*1") or o.endswith("*1+0x0"):
      return ["rr", getReg(r), getReg(o.split("*")[0])]
    return
  if "-" in offs:
    o = -o
  if "+" in r and "*1" in r: # two regs
    r1, r2 = r.split("+")
    r2 = r2.split("*")[0]
    return ["rrc", getReg(r1), getReg(r2), o]
  return ["rc", getReg(r), o]

def isPtr(s):
  return "[" in s and "]" in s

def getConst(s):
  if s.startswith("0x"):
    return int(s[2:], 16)
  return int(s)

def isConst(s):
  return re.search("^(0x)?[0-9a-f]+$", s) != None

def getAddrInSeg(s):
  return ["insn", int(s.split(" ")[0], 16)]

def getFunName(s):
  return s.split("<")[1].split(">")[0]

def dataPtrToConst(p):
  for d in data:
    if d[0] in p[2]:
      return ["c", p[1]-d[1]+d[2]]
  raise BaseException("data not found: %s" % p)

def getInsn(i, ops, name, prevI):
  if i == "nop" or i == "endbr64":
    return []
  elif i == "cdqe": # we only use 1 byte operands
    return []
  elif i == "push":
    return ["push", getReg(ops)]
  elif i == "pop":
    return ["pop", getReg(ops)]
  elif i == "leave": # set sp to bp, then pop bp
    return ["leave"]
  elif i == "ret":
    return ["ret"]
  elif i == "call":
    if "<exit@plt>" in ops:
      return ["exit"]
    else:
      return ["call", getFunName(ops)]
  elif i == "test":
    if ops == "al,al":
      return ["testalal"]
  elif i == "jmp":
    return ["j", getAddrInSeg(ops)]
  elif i == "ja" or i == "jg": # jump if above (unsigned + signed)
    return ["jg", getAddrInSeg(ops)]
  elif i == "jge": # jump if greater or eq (signed)
    return ["jge", getAddrInSeg(ops)]
  elif i == "jle": # jump if less or eq (signed)
    return ["jle", getAddrInSeg(ops)]
  elif i == "jne": # zero == 0
    return ["jne", getAddrInSeg(ops)]
  elif i == "je": # zero == 1
    return ["je", getAddrInSeg(ops)]
  elif i == "sete": # set reg if zero == 0
    return ["sete", getReg(ops)]
  elif i == "setne": # set reg if zero == 1
    return ["setne", getReg(ops)]
  try:
    dst, src = getOps(ops)
  except:
    raise BaseException("unknown insn: %s %s" % (i, ops))
  if i == "mov" or i == "movsx" or i == "movsxd" or i == "movzx":
    if isReg(dst) and isReg(src):
      if getReg(dst) == getReg(src):
        return []
      return ["movrr", getReg(dst), getReg(src)]
    elif isReg(dst) and isConst(src):
      return ["movrc", getReg(dst), getConst(src)]
    elif isReg(dst) and isMem(src):
      return ["movrp", getReg(dst), getMem(src)]
    elif isMem(dst) and isReg(src):
      return ["movpr", getMem(dst), getReg(src)]
    elif isPtr(dst) and isReg(src):
      return ["movpr", getPtr(dst), getReg(src)]
    elif isMem(dst) and isConst(src):
      return ["movpc", getMem(dst), getConst(src)]
    elif isPtr(dst) and isConst(src):
      return ["movpc", getPtr(dst), getConst(src)]
    elif isReg(dst) and isPtr(src):
      return ["movrp", getReg(dst), getPtr(src)]
  elif i == "lea":
    if isReg(dst) and isMem(src): # Move constant mem addr into reg
      return ["learp", getReg(dst), getMem(src)]
    if isReg(dst) and isPtr(src): # Move constant reg+offs into reg
      return ["learp", getReg(dst), getPtr(src)]
  elif i == "cmp":
    if isReg(dst) and isConst(src):
      return ["cmprc", getReg(dst), getConst(src)]
    if isPtr(dst) and isConst(src):
      return ["cmppc", getPtr(dst), getConst(src)]
    if isPtr(dst) and isReg(src):
      return ["cmppr", getPtr(dst), getReg(src)]
  elif i == "add":
    if isReg(dst) and isReg(src):
      return ["addrr", getReg(dst), getReg(src)]
    if isReg(dst) and isConst(src):
      return ["addrc", getReg(dst), getConst(src)]
    elif isPtr(dst) and isConst(src):
      return ["addpc", getPtr(dst), getConst(src)]
  elif i == "sub":
    if isReg(dst) and isConst(src):
      return ["subrc", getReg(dst), getConst(src)]
    if isReg(dst) and isPtr(src):
      return ["subrp", getReg(dst), getPtr(src)]
  elif i == "shr" or i == "sar":
    if isReg(dst) and isConst(src):
      return ["shrrc", getReg(dst), getConst(src)]

  raise BaseException("unknown insn: %s %s" % (i, ops))

def combineInsns(name, insns):
  ret = []
  i = 0
  arr = [i[1] for i in insns]
  stackOffs = 0
  while i < len(insns):
    addr = insns[i][0]
    insn = insns[i][1]
    if len(insn) == 0:
      i += 1
      continue

    # Stack stuff: Make SP the only stack ptr, make stack insns special
    # Remove ['push', 'bp'], ['movrr', 'bp', 'sp'], ['pop', 'bp']
    if (insn[0] == 'push' or insn[0] == 'movrr' or insn[0] == 'pop') and insn[1] == 'bp':
      i += 1
      continue
    # ['subrc', 'sp', X] -> ['inc-sp' X]
    if insn[0] == 'subrc' and insn[1] == 'sp':
      stackOffs = insn[2]
      insn = ['inc-sp', -stackOffs]
    if insn[0] == 'leave':
      insn = ['inc-sp', stackOffs]
    # ['rc', 'bp', X] -> ['rc', 'sp', Y]
    # ['rrc', 'bp', 'a', X] -> ['rrc', 'sp', 'a', Y]
    for j in range(len(insn)):
      if type(insn[j]) == list and insn[j][0] == 'rc' and insn[j][1] == 'bp':
        insn[j] = ['rc', 'sp', insn[j][2]+stackOffs]
      if type(insn[j]) == list and insn[j][0] == 'rrc' and insn[j][1] == 'bp':
        insn[j] = ['rrc', 'sp', insn[j][2], insn[j][3]+stackOffs]

    # Paint the stack green instead of red:
    # ['cmprc', 'a', 255] -> ['cmprc', 'a', 255**2]
    # ['movpc', ['rrc', 'sp', 'a', 16], 255] -> ['movpc', ['rrc', 'sp', 'a', 16], 255**2]
    if (insn[0] == 'cmprc' or insn[0] == 'movpc') and insn[2] == 255:
      insn[2] = 255**2

    # ['cmprc', 'a', 3], ['setne', 'a'], ['testalal'], ['je', 359] -> ['cmprc', 'a', 3] ['je' 359]
    if insn[0] == 'setne' and insn[1] == 'a' and arr[i+1][0] == 'testalal':
      i += 2
      continue
    # "['movrc', 'di', 0/1], ['exit'] -> fail/success
    if insn[0] == 'movrc' and insn[1] == 'di' and arr[i+1][0] == 'exit':
      ret.append([addr, ['fail' if insn[2] == 0 else 'success']])
      i += 2
      continue
    # ['movrp', 'a', ['m', 16480, 'flag']] -> ['movrc', 'a', 0]
    if insn[0].startswith('mov') or insn[0].startswith('lea') and 'p' in insn[0][3:]:
      if type(insn[1]) == list and insn[1][0] == 'm':
        insn[1] = dataPtrToConst(insn[1])
      elif type(insn[2]) == list and insn[2][0] == 'm':
        insn[2] = dataPtrToConst(insn[2])
      if insn[0] == "learp" and insn[2][0] == 'c' : # ['learp', 'si', ['c', 35]] -> ['movrc', 'si', 35]
        insn = ["movrc", insn[1], insn[2][1]]
    ret.append([addr, insn])
    i += 1
  for i in range(len(ret)):
    addr = ret[i][0]
    insn = ret[i][1]
    # ['j', ['insn', 5460]] -> ['j', -10]
    # Change insn address to rel jump
    if len(insn) == 2 and insn[0].startswith('j') and insn[1][0] == "insn":
      for j in range(len(ret)):
        if ret[j][0] >= insn[1][1]:
          insn[1] = j-i
          break
      if len(insn) == 2 and type(insn[1]) == list:
        raise BaseException("index for jump not found %s" % insn)
  for i in range(len(ret)):
    ret[i] = ret[i][1]
    if ret[i] == "testalal":
      raise BaseException("testalal left in %s" % name)
  return ret

def exportSeg(seg):
  insns = []
  prevI = ""
  skipped = False
  name = seg.split("\n")[0].split("<")[1].split(">")[0]
  for line in seg.strip().split("\n")[1:]:
    addr = int(line.split(":")[0].strip(), 16)
    insn = line.split("\t")[-1]
    idx = insn.find(" ")
    if idx == -1:
      i = insn
      ops = ""
    else:
      i = insn[:idx].strip()
      ops = insn[idx:].strip()
      if "crackme" in name:
        # Ignore the following at the start:
        # mov rax,QWORD PTR fs:0x28
        # mov QWORD PTR [rbp-0x8],rax
        # xor eax,eax
        if "fs:" in ops or (i == "00" and "00" in ops) or (i == "xor" and ops == "eax,eax"):
          prevI = i
          continue
        if prevI == "00" and not skipped:
          skipped = True
          continue
    insns.append([addr, getInsn(i, ops, name, prevI)])
    # print(insns[-1])
  return name, combineInsns(name, insns)

def printInsns(segs):
  insns = {}
  ptrs = {}
  insnCount = 0
  for name, seg in segs.items():
    print(name)
    for i in seg:
      insnCount += 1
      print(i)
      insns[i[0]] = True
      for op in i[1:]:
        if type(op) == list:
          ptrs[str(op[0])] = op[1:]
    print("---\n")
  return
  print(insnCount)
  ilist = [i for i in insns]
  ilist.sort()
  print(len(ilist))
  for i in ilist:
    print(i)
  print(len(ptrs))
  for p, ops in ptrs.items():
    print(p, ops)

def loadSegs(filename):
    with open(filename, "r") as f:
      content = f.read()
    segs = {}
    for seg in[s.strip() for s in content.strip().split("---") if len(s.strip()) > 0]:
      seg = seg.split("\n")
      name = seg[0]
      insns = [eval(i) for i in seg[1:]]
      segs[name] = insns
    return segs

def getLocOfSeg(seg):
  for i in range(len(funs)):
    if funs[i] in seg:
      return (i*3, 0) # x, y
  raise BaseException("seg not found: %s" % seg)

def twosCompl(val):
  if val < 0:
    return 256+val
  return val

def operandToPixel(insn, op, xPos, yPos):
  # print(insn, op)
  if insn == "call": # Pixel position of fun to call
    x, y = getLocOfSeg(op)
    # Store the distance needed to move.
    return [x-xPos, yPos-y, 128]
  if type(op) == list and op[0] == 'c': # Constant-only pointer, convert to const
    op = op[1]
  if type(op) == str: # reg
    if op not in regNums:
      raise BaseException("unknown reg: %s" % op)
    n = regNums[op]
    return [n, n, n]
  elif type(op) == int: # const
    # twos complement on 3 bytes
    if op < 0:
      op = 256**3 + op
    # little endian
    return [op%256, (op>>8)%256, (op>>16)%256]
  elif type(op) == list: # ptr: r+c
    # Remove sp: included in opcode bit
    # ['rc', 'sp', X] -> ['c', X]; ['rrc', 'sp' 'a', X] -> ['rc', 'a', X]
    if op[0] == 'rc' and op[1] == 'sp':
      op = ['c', op[2]]
    elif op[0] == 'rrc' and op[1] == 'sp':
      op = ['rc', op[2], op[3]]
    op = op[1:]
    color = [0, 0, 0] # 0 in reg field means reg not present
    if type(op[0]) == str: # reg 1
      if op[0] not in regNums:
        raise BaseException("unknown reg: %s" % op[0])
      color[0] = regNums[op[0]]
      op = op[1:]
    if len(op) == 0:
      return color
    if type(op[0]) == str: # reg 2
      if op[0] not in regNums:
        raise BaseException("unknown reg: %s" % op[0])
      color[1] = regNums[op[0]]
      op = op[1:]
    if len(op) == 0:
      return color
    if type(op[0]) == int: # const
      if op[0] > 128 or op[0] < -127:
        raise BaseException("const operand doesn't fit into unsigned byte: %s" % op)
      # twos complement
      color[2] = twosCompl(op[0])
    else:
      raise BaseException("unknown operand type: %s" % op)
    return color
  else:
    raise BaseException("unknown operand type: %s" % op)

def addColor(data, xPos, yPos, insn):
  i = insn[0]
  # print(i)
  color = (255, 255, 255)
  for code, col in opcodes.items():
    if i.startswith(code):
      color = col
      break
  if color[0] == 255 and color[1] == 255 and color[2] == 255:
    raise BaseException("unknown insn: %s" % insn)
  data[yPos][xPos] = [color[0], color[1], color[2]]
  if insn[0] == "ret":
    insn = ["ret", yPos] # ret operand contains how much to jump back up.


  if len(insn) == 1: # No operands, nothing else to do.
    return

  # Modify lsbs based on operand types.
  if len(i) == 5: # movXY, leaXY, etc.
    # print(data[yPos][xPos])
    # 1st lsb: (op1_is_reg, op1_is_ptr, op1_is_const)
    if i[3] == 'r':
      data[yPos][xPos][0] |= 1
    elif i[3] == 'p':
      data[yPos][xPos][1] |= 1
      if insn[1][0] == 'c': # Constant-only pointer, mark separately
        data[yPos][xPos][2] |= 1
      if insn[1][1] == 'sp': # Stack-relative addr, mark separately
        data[yPos][xPos][0] |= 1
    elif i[3] == 'c':
      data[yPos][xPos][2] |= 1
    else:
      raise BaseException("unknown operand types: %s" % insn)
    # 2nd lsb: (op2_is_reg, op2_is_ptr, op2_is_const)
    if i[4] == 'r':
      data[yPos][xPos][0] |= 2
    elif i[4] == 'p':
      data[yPos][xPos][1] |= 2
      if insn[2][0] == 'c': # Constant-only pointer, mark separately
        data[yPos][xPos][2] |= 2
      if insn[2][1] == 'sp': # Stack-relative addr, mark separately
        data[yPos][xPos][0] |= 2
    elif i[4] == 'c':
      data[yPos][xPos][2] |= 2
    else:
      raise BaseException("unknown operand types: %s" % insn)
    # print(data[yPos][xPos])
  elif i.startswith("j"):
    # lsb: (eq, neq)
    # 2nd lsb: (l, g)
    if i == "j": # everything
      data[yPos][xPos][0] |= 3
      data[yPos][xPos][1] |= 3
    elif i == "je": # only eq
      data[yPos][xPos][0] |= 1
    elif i == "jne": # only neq
      data[yPos][xPos][1] |= 1
    elif i == "jg": # only g
      data[yPos][xPos][1] |= 2
    elif i == "jl": # only l
      data[yPos][xPos][0] |= 2
    elif i == "jge": # eq and g
      data[yPos][xPos][0] |= 1
      data[yPos][xPos][1] |= 2
    elif i == "jle": # eq and l
      data[yPos][xPos][0] |= 1
      data[yPos][xPos][0] |= 2
    else:
      raise BaseException("unknown jump type: %s" % insn)

  # Add operands.
  op1 = insn[1]
  data[yPos][xPos+1] = operandToPixel(i, op1, xPos, yPos)
  # print(data[yPos][xPos+1])
  if len(insn) == 2:
    return
  op2 = insn[2]
  data[yPos][xPos+2] = operandToPixel(i, op2, xPos, yPos)
  # print(data[yPos][xPos+2])
  if len(insn) > 3:
    raise BaseException("unknown operand count: %s" % insn)

def addPixelsForSeg(data, xPos, name, seg):
  # print(name)
  yPos = 0
  # for insn in seg:
  #   print(insn)
  # raise BaseException("break")
  for insn in seg:
    addColor(data, xPos, yPos, insn)
    yPos += 1

def convertToPixels(segs):
  h = max([len(seg) for name, seg in segs.items()])
  # print(h)
  w = len(segs)*3 # 3 pixels for each insn
  bitmap = [[(255, 255, 255) for x in range(w)] for y in range(h)]
  for i in range(len(funs)):
    seg, name = [(seg, name) for name, seg in segs.items() if funs[i] in name][0]
    addPixelsForSeg(bitmap, i*3, name, seg)
  return bitmap

def initMemory():
  flag = [(255, 255, 255) for c in range(35)]
  sFlag = [(255, 255, 255) for i in range(30)]
  sortArr = [23,14,7,18,12,1,28,15,26,0,5,21,27,3,11,24,13,2,8,22,6,10,29,19,17,9,20,4,16,25]
  sortArr = [(i, 0, 0) for i in sortArr]
  if len(sortArr) != 30:
    raise BaseException("wrong len for sortArr: %d" % len(sortArr))
  cmpArr = [1,1,1,3,1,1,1,2,1,4,1,1,1,2,3,1,1,3,1,1,2,1,3,1,1,2,3,1,1,2,2,3,1,1,2,2,2,4,1,3,1,2,1,1,1,4,1,2,1,1,3,1,2,1,1,2,4,1,2,1,3,1,2,1,2,1,4,1,2,1,2,1,4,1,2,1,2,3,1,2,3,1,2,2,1,1,4,1,2,2,1,1,4,1,2,2,1,1,4,1,2,2,1,1,4,1,2,2,1,1,4,1,2,2,1,3,1,2,2,1,2,4,1,2,2,1,2,4,1,2,2,1,2,4,1,2,2,3,1,2,2,2,1,4,1,2,2,2,1,4,1,2,2,2,1,4,1,2,2,2,1,4,1,2,2,2,1,4,1,2,2,2,1,4,1,2,2,2,3,1,2,2,2,2,4,1,2,2,2,2,4,1,2,2,2,2,4,1,2,2,2,2,4,1,2,2,2,2,4,1,2,2,2,2,4,1,2,2,2,2,4,3,2,1,1,1,3,2,1,1,1,2,4,2,1,1,3,2,1,1,2,1,4,2,1,1,2,3,2,1,1,2,2,4,2,1,1,2,2,4,2,1,1,2,2,4,2,1,1,2,2,4,2,1,1,2,2,4,2,1,3,2,1,2,1,1,4,2,1,2,1,3,2,1,2,1,2,4,2,1,2,1,2,4,2,1,2,3,2,1,2,2,3,2,1,2,2,2,4,2,1,2,2,2,4,2,3,2,2,1,1,3,2,2,1,1,2,4,2,2,1,1,2,4,2,2,1,3,2,2,1,2,1,4,2,2,1,2,3,2,2,1,2,2,4,2,2,1,2,2,4,2,2,1,2,2,4,2,2,3,2,2,2,1,3,2,2,2,3,2,2,2,2,1,4,2,2,2,2,1,4,2,2,2,2,3,2,2,2,2,2,4,2,2,2,2,2,4,2,2,2,2,2,4]
  cmpArr = [(i, 0, 0) for i in cmpArr]
  if len(cmpArr) != 424:
    raise BaseException("wrong len for cmpArr: %d" % len(cmpArr))
  cmpPos = [(0, 0, 0)]
  mem = flag+sFlag+sortArr+cmpArr+cmpPos
  if len(mem) != 520:
    raise BaseException("wrong len for mem: %d" % len(mem))
  mem2d = [[(255, 255, 255) for x in range(25)] for y in range(21)]
  for i in range(len(mem)):
    mem2d[i//25][i%25] = mem[i]
  return mem2d

def exportImage(bitmap, filename):
  array = np.array(bitmap, dtype=np.uint8)
  img = Image.fromarray(array)
  img.save(filename)

INSN_TXT = False

try:
  if INSN_TXT:
    with open("crackme.disas", "r") as f:
      content = f.read()
    segStrs = [s.strip() for s in content.split("\n\n")]
    segStrs = [s for s in segStrs if any(f in s.split(" ")[1].split(">:")[0][1:] for f in funs)]
    segs = {}

    for seg in segStrs:
      name, sg = exportSeg(seg)
      segs[name] = sg
      # print(name, sg)
    printInsns(segs)
  else:
    segs = loadSegs("insns.txt")
    bitmap = convertToPixels(segs)
    for y in range(len(bitmap)):
      r = ""
      for x in range(len(bitmap[0])):
        b = bitmap[y][x]
        r += "#{:02x}{:02x}{:02x} ".format(b[0], b[1], b[2])
      print(r)
    exportImage(bitmap, "c.png")
    memory = initMemory()
    exportImage(memory, "m.png")

except BaseException as e:
  print(e)
  # raise e

# 177 instructions in total
# 520 bytes of data
# 12 unique insns, (succ/fail, mov/lea, sub/add/shr, cmp/j, call/ret/inc-sp)
# operands: either reg, ptr, const
# ptr: reg+reg+const

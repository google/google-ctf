# Copyright 2025 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from z3 import *
import time
from flag import flag
import sys


spec = """
ISA:
- 4 8-bit registers
- 256 bytes of instruction memory
  - first 128 are user programs
  - second 128 are kernel code
- 256 bytes of data memory
  - first 128 are user-accessible
  - second 128 are kernel-only

Instructions:
rdtsc rX (kernel only)
  0000'00rr
putc rX (kernel only)
  0000'01rr
ldi rX, imm
  0000'10rr
syscall
  0000'110x
- will jump into kernel location 130. Return address will be put in r0.
- kernel code handles syscall depending on r1, then sysret back to r0.
- r1 == 0: exit()
- r1 == 1: time() -> returns rdtsc in r1
- r1 == 2: putc(r2)
sysret (kernel only)
  0000'1110
halt
  0000'1111
load rX, [rY]
  0001'XXYY
store [rX], rY
  0010'YYXX
add rX, rY
  0011'XXYY
jmp rX
  01xx'xxrr
jz rX==0, rY
  1xxx'XXYY


Combinatorial instruction decoder specification:
Inputs:
- is_root_now
- ins_0..ins_7
- r0_0..r0_7, ..., r3_0..r3_7
Outputs:
- is_rdtsc, is_putc, ... is_jz
- security_exception
"""
finished_circuit = False
gates = {}

def verify():
  global finished_circuit
  # TODO: add check number of gates

  outputs = ["is_rdtsc", "is_putc", "is_ldi", "is_syscall", "is_sysret", "is_halt", "is_load", "is_store", "is_add", "is_jmp", "is_jz"]
  outputs += ["security_exception"]

  basic_inputs = ["is_root_now"]
  for i in range(8):
    basic_inputs.append("ins_%d" % i)
    basic_inputs.append("r0_%d" % i)
    basic_inputs.append("r1_%d" % i)
    basic_inputs.append("r2_%d" % i)
    basic_inputs.append("r3_%d" % i)

  for o in outputs:
    if o not in gates:
      print("%s not implemented." % o)
      return

  for g in gates:
    a, b = gates[g]
    if a not in gates and a not in basic_inputs:
      print("Wire %s not connected." % a)
      return
    if b not in gates and b not in basic_inputs:
      print("Wire %s not connected." % b)
      return

  v = {}
  for g in list(gates) + basic_inputs:
    v[g] = Bool(g)

  s = Solver()
  for g in gates:
    a, b = gates[g]
    s.add(v[g] == Not(And(v[a], v[b])))

  res = s.check()
  if res == unknown:
    print("Error?")
    return
  if res == unsat:
    print("Circuit unstable.")
    return

  constraints = []
  # TODO
  constraints.append(v["is_jz"]      == v["ins_7"])
  constraints.append(v["is_jmp"]     == ~v["ins_7"] & v["ins_6"])
  constraints.append(v["is_add"]     == ~v["ins_7"] & ~v["ins_6"] & v["ins_5"] & v["ins_4"])
  constraints.append(v["is_store"]   == ~v["ins_7"] & ~v["ins_6"] & v["ins_5"] & ~v["ins_4"])
  constraints.append(v["is_load"]    == ~v["ins_7"] & ~v["ins_6"] & ~v["ins_5"] & v["ins_4"])
  constraints.append(v["is_halt"]  == ~v["ins_7"] & ~v["ins_6"] & ~v["ins_5"] & ~v["ins_4"] & v["ins_3"] & v["ins_2"] & v["ins_1"] & v["ins_0"])
  constraints.append(v["is_sysret"]  == ~v["ins_7"] & ~v["ins_6"] & ~v["ins_5"] & ~v["ins_4"] & v["ins_3"] & v["ins_2"] & v["ins_1"] & ~v["ins_0"])
  constraints.append(v["is_syscall"] == ~v["ins_7"] & ~v["ins_6"] & ~v["ins_5"] & ~v["ins_4"] & v["ins_3"] & v["ins_2"] & ~v["ins_1"])
  constraints.append(v["is_ldi"]     == ~v["ins_7"] & ~v["ins_6"] & ~v["ins_5"] & ~v["ins_4"] & v["ins_3"] & ~v["ins_2"])
  constraints.append(v["is_putc"]    == ~v["ins_7"] & ~v["ins_6"] & ~v["ins_5"] & ~v["ins_4"] & ~v["ins_3"] & v["ins_2"])
  constraints.append(v["is_rdtsc"]   == ~v["ins_7"] & ~v["ins_6"] & ~v["ins_5"] & ~v["ins_4"] & ~v["ins_3"] & ~v["ins_2"])

  is_kernel_addr = Or([
      ~v["ins_0"] & ~v["ins_1"] & v["r0_7"],
      v["ins_0"] & ~v["ins_1"]  & v["r1_7"],
      ~v["ins_0"] & v["ins_1"]  & v["r2_7"],
      v["ins_0"] & v["ins_1"]   & v["r3_7"],
  ])

  constraints.append(v["security_exception"] == ~v["is_root_now"] & Or([
      v["is_rdtsc"], v["is_putc"], v["is_sysret"], # <- is kernel instruction
      And(Or(v["is_store"], v["is_load"]), is_kernel_addr) # <- is memory instruction with kernel address
  ]))
  # TODO: test later manually if my circuit actually obeys these laws
  # TODO: write good circuit
  # TODO: write malicious circuit.


  s.add(Not(And(
      constraints
  )))
  res = s.check()
  if res == unknown:
    print("Error?")
    return
  if res == unsat:
    print("Formal verification passed!")
  else:
    print("Formal verification error. Example input/output:")
    model = s.model()
    for i in basic_inputs:
      x = model[v[i]]
      if x is not None:
        print(i, x)
    for o in outputs:
      x = model[v[o]]
      if x is not None:
        print(o, x)
    return

  print("Looks good!")
  finished_circuit = True

import string
def check(name):
  if name.startswith("_"): return False
  if any(c not in string.ascii_letters + string.digits + "_" for c in name): return False
  return True

def menu():
  global gates
  print("1. Print specification.")
  print("2. Clear design.")
  print("3. Add gate.")
  print("4. Print design.")
  print("5. Verify design.")
  try:
    choice = int(input())
  except EOFError:
    sys.exit(0)
  except:
    return

  if choice == 1:
    print(spec)
  elif choice == 2:
    gates = {}
  elif choice == 3:
    print("Write 3 wire names (e.g. 'C A B') to add NAND gate C = A NAND B")
    c, a, b = input().strip().split()
    if not check(a) or not check(b) or not check(c):
      print("Invalid name.")
      return
    if c in gates:
      print("Wire already exists.")
      return
    gates[c] = (a, b)
    print("Added.")
  elif choice == 4:
    for c in gates:
      a, b = gates[c]
      print("%s = %s NAND %s" % (c, a, b))
  elif choice == 5:
    verify()
  else:
    print("???")

def run_nand(known, what):
  if what in known:
    return known[what]

  a, b = gates[what]
  a = run_nand(known, a)
  b = run_nand(known, b)

  known[what] = not (a and b)
  return known[what]

def run(code):
  memory = [0] * 256
  for i, c in enumerate(flag):
    memory[i+128] = ord(c)

  pc = 0
  regs = [0, 0, 0, 0]
  is_root_now = False
  steps = 0
  while True:
    time.sleep(0.01) # It's a slow CPU...

    steps += 1
    if steps > 10000:
      print("Step limit reached.")
      return

    ins = code[pc]
    pc += 1

    known = {}
    known["is_root_now"] = is_root_now
    for i in range(8):
      known["ins_%d" % i] = (ins >> i) & 1
      for r in range(4):
        known["r%d_%d" % (r, i)] = (regs[r] >> i) & 1

    outputs = ["is_rdtsc", "is_putc", "is_ldi", "is_syscall", "is_sysret", "is_halt", "is_load", "is_store", "is_add", "is_jmp", "is_jz"]
    type = []
    for o in outputs:
      if run_nand(known, o):
        type.append(o)

    assert len(type) == 1

    # TODO: remove debug
    #print("State:", pc-1, regs, is_root_now, type[0])

    if run_nand(known, "security_exception"):
      print("SECURITY EXCEPTION. HALTING.")
      return

    bottom = ins & 3
    second = (ins >> 2) & 3

    if known["is_jmp"] or known["is_jz"]:
      cond = True
      if known["is_jz"]:
        cond = regs[second] == 0

      if cond:
        pc = regs[bottom]
    elif known["is_add"]:
      regs[second] += regs[bottom]
      regs[second] &= 255
    elif known["is_store"]:
      memory[regs[bottom]] = regs[second]
    elif known["is_load"]:
      regs[second] = memory[regs[bottom]]
    elif known["is_halt"]:
      print("HALT.")
      return
    elif known["is_sysret"]:
      pc = regs[0]
      is_root_now = False
    elif known["is_syscall"]:
      regs[0] = pc
      pc = 130
      is_root_now = True
    elif known["is_ldi"]:
      regs[bottom] = code[pc]
      pc += 1
    elif known["is_putc"]:
      print(chr(regs[bottom]), end="")
      sys.stdout.flush()
      # TODO
      #print("printing", regs[bottom], chr(regs[bottom]))
    elif known["is_rdtsc"]:
      regs[bottom] = int(time.time()) % 10
    else:
      print("Should not happen...")
      return

def get_and_run():
  print("Ok. The CPU design was sent to the factory, and we got the chip now.")
  print("Let's run some code!")
  print("Example: 09020a480c0a690c0a210c0a200c0a540c0a680c0a650c0a200c0a740c0a690c0a6d0c0a650c0a200c0a690c0a730c0a200c0a780c0a780c0a3a0c0a780c0a780c0a3a0c0a780c09010c0b303b09020c0a0a0c09000c") # TODO
  print("Input (hex-encoded) user code (up to 128 bytes):")

  HALT = b"\x0f"
  code = bytes.fromhex(input().strip())[:128]
  code += HALT * (128 - len(code))

  KERNEL_CODE = bytes.fromhex("0f0f 0b91 870bff37 0b92 870bff37 0b96 87 0f 0209010e 0609020e")

  KERNEL_CODE += HALT * (128 - len(KERNEL_CODE))
  code += KERNEL_CODE

  run(code)

def main():
  print("Implement the CPU decoder circuit!")
  while not finished_circuit:
    menu()
  get_and_run()


if __name__ == "__main__":
  main()

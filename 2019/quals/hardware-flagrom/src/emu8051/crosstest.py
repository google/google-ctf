# Copyright 2019 Google LLC
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

import subprocess
import random
import os

BYTES_COUNT = 0x10000
STEP_COUNT = 50

S51_LOAD = 'file "tmp/test.ihex"'
S51_INFO_REG = 'info registers'
S51_STEP = 'step'
S51_QUIT = 'quit'


def perform_test():
  with open("tmp/test", "wb") as f:
    f.write(os.urandom(BYTES_COUNT))

  subprocess.check_call(["srec_cat", "tmp/test", "-Binary", "-Output", "tmp/test.ihex", "-intel"])

  p = subprocess.Popen(["s51"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.PIPE)
  cmds = [
    "fill iram 0 0xff 0",
    "fill sfr 0x80 0xff 0",
    "fill xram 0 0xffff 0",
    "fill rom 0 0xffff 0",
    S51_LOAD,
    S51_INFO_REG
  ]

  cmds.extend([S51_STEP] * STEP_COUNT)
  cmds.append(S51_QUIT)

  cmd = '\n'.join(cmds)
  stdout, stderr = p.communicate(cmd)

  """
  print "-" * 70
  print stdout
  print "-" * 70
  print stderr
  print "-" * 70
  """

  result = []
  instr = []

  if ('TCON' in stdout or
      'SCON' in stdout or
      'IE' in stdout):
    print "Ignoring results due to banned keyword appearing."
    return True

  s = stdout.split("Stop at ")[1:]
  for r in s:
    lines = r.splitlines()

    instr.append(lines[6].strip())

    pc = int(lines[0].split(':')[0][2:], 16)
    result.append("pc: %.4x" % pc)

    regset = lines[1][5:][:23]
    #print lines[1]
    result.append("regset: %s" % regset)

    a = int(lines[2].split("ACC=")[1].strip().split(" ")[0], 16)
    result.append("a: %.2x" % a)

    psw = int(lines[3].split("PSW=")[1].strip().split(" ")[0], 16)
    # NOTE: Ignore parity flag for now
    psw &= 0xfe
    result.append("psw: %.2x" % psw)

    dptr = int(lines[5].split("DPTR=")[1].strip().split(" ")[0], 16)
    result.append("dptr: %.4x" % dptr)
    result.append("")

  result_s51 = result

  p = subprocess.Popen(["./emu8051_crosstest", "tmp/test"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.PIPE)
  stdout, stderr = p.communicate("%i" % STEP_COUNT)

  result_emu8051 = stdout.splitlines()

  print "      %-40s     %-40s" % ("-- s51", "-- emu8051")
  i = 0
  ic = 0
  all_ok = True
  break_soon = 15
  while i < max(len(result_s51), len(result_emu8051)):
    left = "-"
    right = "-"

    if i < len(result_s51):
      left = result_s51[i]

    if i < len(result_s51):
      right = result_emu8051[i]

    res = "OK"
    if left.strip() != right.strip():
      res = "!!"
      all_ok = False

    print "%s    %-40s     %-40s" % (res, left, right)
    if left.startswith("dptr:"):
      print
      print instr[ic].replace("?", "---> ")
      ic += 1

    i += 1

    if all_ok is False:
      break_soon -= 1
      if break_soon == 0:
        print "----> Fast break (skipping rest of content)."
        break

  return all_ok


test_i = 0
while True:
  print "-" * 70, "TEST %i" % test_i
  test_i +=1
  if not perform_test():
    break




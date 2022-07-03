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

import sys
exceptions = {
    0x00: ( "INS_NOP", ),
    0x10: ( "INS_JBC", "ARG_BIT", "ARG_REL8" ),
    0x20: ( "INS_JB", "ARG_BIT", "ARG_REL8" ),
    0x30: ( "INS_JNB", "ARG_BIT", "ARG_REL8" ),
    0x40: ( "INS_JC", "ARG_REL8" ),
    0x50: ( "INS_JNC", "ARG_REL8" ),
    0x60: ( "INS_JZ", "ARG_REL8" ),
    0x70: ( "INS_JNZ","ARG_REL8"  ),
    0x80: ( "INS_SJMP", "ARG_REL8" ),
    0x90: ( "INS_MOV", "ARG_DPTR", "ARG_IMM16" ),
    0xA0: ( "INS_ORL", "ARG_C", "ARG_NEG_BIT" ),
    0xB0: ( "INS_ANL", "ARG_C", "ARG_NEG_BIT" ),
    0xC0: ( "INS_PUSH", "ARG_DIRECT_IRAM" ),
    0xD0: ( "INS_POP", "ARG_DIRECT_IRAM" ),
    0xE0: ( "INS_MOVX", "ARG_A", "ARG_DPTR_INDIRECT_XRAM" ),
    0xF0: ( "INS_MOVX", "ARG_DPTR_INDIRECT_XRAM", "ARG_A" ),

    0x02: ( "INS_LJMP", "ARG_IMM16" ),
    0x12: ( "INS_LCALL", "ARG_IMM16" ),
    0x22: ( "INS_RET", ),
    0x32: ( "INS_RETI", ),
    0x42: ( "INS_ORL", "ARG_DIRECT_IRAM", "ARG_A" ),
    0x52: ( "INS_ANL", "ARG_DIRECT_IRAM", "ARG_A" ),
    0x62: ( "INS_XRL", "ARG_DIRECT_IRAM", "ARG_A" ),
    0x72: ( "INS_ORL", "ARG_C", "ARG_BIT" ),
    0x82: ( "INS_ANL", "ARG_C", "ARG_BIT" ),
    0x92: ( "INS_MOV", "ARG_BIT", "ARG_C" ),
    0xA2: ( "INS_MOV", "ARG_C", "ARG_BIT" ),
    0xB2: ( "INS_CPL", "ARG_BIT" ),
    0xC2: ( "INS_CLR", "ARG_BIT" ),
    0xD2: ( "INS_SETB", "ARG_BIT" ),
    0xE2: ( "INS_MOVX", "ARG_A", "ARG_R0_INDIRECT_XRAM" ),
    0xF2: ( "INS_MOVX", "ARG_R0_INDIRECT_XRAM", "ARG_A" ),

    0x03: ( "INS_RR", "ARG_A" ),
    0x13: ( "INS_RRC", "ARG_A" ),
    0x23: ( "INS_RL", "ARG_A" ),
    0x33: ( "INS_RLC", "ARG_A" ),
    0x43: ( "INS_ORL", "ARG_DIRECT_IRAM", "ARG_IMM8" ),
    0x53: ( "INS_ANL", "ARG_DIRECT_IRAM", "ARG_IMM8" ),
    0x63: ( "INS_XRL", "ARG_DIRECT_IRAM", "ARG_IMM8" ),
    0x73: ( "INS_JMP", "ARG_A_DPTR" ),
    0x83: ( "INS_MOVC", "ARG_A", "ARG_A_PC_INDIRECT_PMEM" ),
    0x93: ( "INS_MOVC", "ARG_A", "ARG_A_DPTR_INDIRECT_PMEM" ),
    0xA3: ( "INS_INC", "ARG_DPTR" ),
    0xB3: ( "INS_CPL", "ARG_C" ),
    0xC3: ( "INS_CLR", "ARG_C" ),
    0xD3: ( "INS_SETB", "ARG_C" ),
    0xE3: ( "INS_MOVX", "ARG_A", "ARG_R1_INDIRECT_XRAM" ),
    0xF3: ( "INS_MOVX", "ARG_R1_INDIRECT_XRAM", "ARG_A" ),

    0x04: ( "INS_INC", "ARG_A" ),
    0x14: ( "INS_DEC", "ARG_A" ),
    0x24: ( "INS_ADD", "ARG_A", "ARG_IMM8" ),
    0x34: ( "INS_ADDC", "ARG_A", "ARG_IMM8" ),
    0x44: ( "INS_ORL", "ARG_A", "ARG_IMM8" ),
    0x54: ( "INS_ANL", "ARG_A", "ARG_IMM8" ),
    0x64: ( "INS_XRL", "ARG_A", "ARG_IMM8" ),
    0x74: ( "INS_MOV", "ARG_A", "ARG_IMM8" ),
    0x84: ( "INS_DIV", "ARG_A", "ARG_B" ),
    0x94: ( "INS_SUBB", "ARG_A", "ARG_IMM8" ),
    0xA4: ( "INS_MUL", "ARG_A", "ARG_B" ),
    0xB4: ( "INS_CJNE", "ARG_A", "ARG_IMM8", "ARG_REL8" ),
    0xC4: ( "INS_SWAP", "ARG_A" ),
    0xD4: ( "INS_DA", "ARG_A" ),
    0xE4: ( "INS_CLR", "ARG_A" ),
    0xF4: ( "INS_CPL", "ARG_A" ),

    0xA5: ( "INS_UNDEFINED", ),

    0xB5: ( "INS_CJNE", "ARG_A", "ARG_DIRECT_IRAM", "ARG_REL8" ),

    0xD6: ( "INS_XCHD", "ARG_A", "ARG_R0_INDIRECT_IRAM"),
    0xD7: ( "INS_XCHD", "ARG_A", "ARG_R1_INDIRECT_IRAM"),
}

unique_opcodes = set()

for i in xrange(0x100):
  ins = "INS_UNDEFINED"
  arg1 = "ARG_NONE"
  arg2 = "ARG_NONE"
  arg3 = "ARG_NONE"

  while True:
    if i in exceptions:
      ins, arg1, arg2, arg3 = (exceptions[i] + ("ARG_NONE", "ARG_NONE", "ARG_NONE"))[:4]
      break

    hi = i & 0xf0
    lo = i & 0x0f


    # AJMP, ACALL
    if lo == 1:
      if (hi & 0x10) == 0:
        ins = "INS_AJMP"
      else:
        ins = "INS_ACALL"
      arg1 = "ARG_IMM11"
      break

    # Regular instructions.
    ins = {
        0x00: "INS_INC",
        0x10: "INS_DEC",
        0x20: "INS_ADD",
        0x30: "INS_ADDC",
        0x40: "INS_ORL",
        0x50: "INS_ANL",
        0x60: "INS_XRL",
        0x70: "INS_MOV",
        0x80: "INS_MOV",
        0x90: "INS_SUBB",
        0xA0: "INS_MOV",
        0xB0: "INS_CJNE",
        0xC0: "INS_XCH",
        0xD0: "INS_DJNZ",
        0xE0: "INS_MOV",
        0xF0: "INS_MOV"
    }[hi]

    if 8 <= lo <= 0xf:
      argn = "ARG_R"
    elif lo == 6:
      argn = "ARG_R0_INDIRECT_IRAM"
    elif lo == 7:
      argn = "ARG_R1_INDIRECT_IRAM"
    elif lo == 5:
      argn = "ARG_DIRECT_IRAM"

    if ins in { "INS_INC", "INS_DEC" }:
      arg1 = argn
    elif ins in { "INS_ADD", "INS_ADDC", "INS_ORL", "INS_ANL", "INS_XRL", "INS_SUBB", "INS_XCH" } or hi in { 0xE0 }:
      arg1 = "ARG_A"
      arg2 = argn
    elif hi == 0x70:
      arg1 = argn
      arg2 = "ARG_IMM8"
    elif hi == 0x80:
      arg1 = "ARG_DIRECT_IRAM"
      arg2 = argn
    elif hi == 0xA0:
      arg1 = argn
      arg2 = "ARG_DIRECT_IRAM"
    elif hi == 0xB0:
      arg1 = argn
      arg2 = "ARG_IMM8"
      arg3 = "ARG_REL8"
    elif hi == 0xD0:
      arg1 = argn
      arg2 = "ARG_REL8"
    elif hi == 0xF0:
      arg1 = argn
      arg2 = "ARG_A"
    else:
      sys.exit("sth went wrong at %.2x" % i)

    break

  unique_opcodes.add(ins)
  print "    /* %.2X */ { instruction_t::%-13s, arg_t::%-22s, arg_t::%-22s, arg_t::%-22s }," % (i, ins, arg1, arg2, arg3)

"""
print
print

unique_opcodes = list(unique_opcodes)
unique_opcodes = sorted(unique_opcodes)

del unique_opcodes[unique_opcodes.index("INS_UNDEFINED")]
unique_opcodes.insert(0, "INS_UNDEFINED")
for k in unique_opcodes:
  print "    %s," % k

"""

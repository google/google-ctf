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
import sys, string, collections

lines = open(sys.argv[1]).readlines()
lines = [line.split(";")[0] for line in lines]
lines = [line.strip() for line in lines]
lines = [line for line in lines if line]

label_to_pc = {}

def out(s):
    global full
    for c in s:
        o = ord(c)
        if pc >= 200 and pc <= label_to_pc.get("endcode", 1000):
            o ^= ord('T')
        full += '\\x{:02x}'.format(o)

prev = ""
for passnum in range(5):
    full = ""
    def geti(s):
        try:
            return int(s)
        except:
            if s in label_to_pc:
                return label_to_pc[s]
            elif passnum == 0:
                return 0
            else:
                assert False, s


    pc = 0
    for line in lines:
        if passnum == 0:
            print("%03d: %s" % (pc, line))
        if line.startswith(".org"):
            new = int(line.split()[1])
            out("\x00" * (new-pc))
            pc = new
            continue
        if ":" in line:
            label = line.strip(":")
            label_to_pc[label] = pc
            continue

        words = line.split()
        words = [word.strip(",") for word in words]
        op, args = words[0], words[1:]

        ins = None
        if op == "endfun":
            ins = "\x00"
        elif op == "call":
            ins = "%" + str(geti(args[0])) + "C"
        elif op.startswith("call"):
            ch = op[4]
            dst = str(geti(args[0]))
            assert args[1][0] == 'r'
            src = args[1][1:]
            ins = "%" + ch + dst + "." + src + "C"
        elif op == "%s":
            ins = "%s"
        else:
            dst, src = args
            if dst[0] == 'r':
                dstch = ""
                dsti = str(int(dst[1:]))
            else:
                assert dst[0] == "["
                dst = dst.strip("[").strip("]")
                if dst[0] == 'r':
                    dstch = "+"
                    dsti = str(geti(dst[1:]))
                else:
                    dstch = "-"
                    dsti = str(geti(dst))

            if src[0] == 'r':
                srcch = "l"
                srci = str(int(src[1:]))
            elif src[0] == '[':
                src = src.strip("[").strip("]")
                if src[0] == 'r':
                    srcch = "h"
                    srci = str(geti(src[1:]))
                else:
                    srcch = "hh"
                    srci = str(geti(src))
            else:
                srcch = "ll"
                srci = str(geti(src))

            opch = None
            if op == "debug":
                opch = "D"
            elif op == "mov":
                opch = "M"
            elif op == "add":
                opch = "S"
            elif op == "sub":
                opch = "O"
            elif op == "mul":
                opch = "X"
            elif op == "div":
                opch = "V"
            elif op == "mod":
                opch = "N"
            elif op == "shl":
                opch = "L"
            elif op == "shr":
                opch = "R"
            elif op == "xor":
                opch = "E"
            elif op == "and":
                opch = "I"
            elif op == "or":
                opch = "U"
            else:
                assert False

            ins = "%" + dstch + dsti + "." + srci + srcch + opch


        if op == "endfun":
            pc += 1
        else:
            pc += len(ins)
        out(ins)

    if prev == full:
        print("Converged.")
        break
    prev = full

if prev != full:
    print("Not converged!")
open(sys.argv[2], "w").write('"' + full + '"\n')


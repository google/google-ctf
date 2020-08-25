# Copyright 2020 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
import sys

# Usage: python3 asm.py source.s scaffold.c output.c
assembly = open(sys.argv[1]).readlines()
assembly = [line.split(";")[0].strip().replace(",", "") for line in assembly]
assembly = [line for line in assembly if line]

label_to_pc = {}

code = ["\x00"] * 65536


def reg_to_int(r):
    assert r[0] == 'r'
    return int(r[1:])*2 + 8


def get_const(label):
    try:
        n = int(label, 0)
        return str(n % 2**16)
    except:
        if passnum == 1:
            n = label_to_pc[label]
        else:
            n = label_to_pc.get(label, 0)

        return "{:05d}".format(n % 2**16)

def dst_to_num(dst):
    if dst[0] == 'r':
        return int(dst[1:])*2+9
    elif dst == "dptr":
        return 7
    elif dst == "*dptr":
        return 6
    else:
        print("Oops")
        raise Exception("Invalid dst: " + dst)

def src_to_str(src):
    if src[0] == 'r':
        return "*{}$".format(int(src[1:])*2+8)
    elif src == "dptr":
        return "*6$"
    elif src == "*dptr":
        return "*5$"
    else:
        return get_const(src)

for passnum in range(2):
    pc = 0
    print("Pass #" + str(passnum))
    for i, line in enumerate(assembly):
        label_to_pc["_" + str(i)] = pc
        if ":" in line:
            # A label.
            name = line.split(":")[0].strip()
            label_to_pc[name] = pc
        elif line[0] == ".":
            # Directive.
            line = line.split()
            name = line[0]
            args = line[1:]
            if name == ".org":
                pc = int(args[0], 0)
            elif name == ".equ":
                label, val = args
                label_to_pc[label] = int(val, 0)
            elif name == ".db":
                for a in args:
                    code[pc] = chr(int(a, 0)%256)
                    pc += 1
            elif name == ".dw":
                for a in args:
                    code[pc] = chr(int(a, 0)&255)
                    code[pc+1] = chr(int(a, 0)>>8)
                    pc += 2
            else:
                print("Oops")
                raise Exception("Unknown directive: " + name)
        else:
            line = line.split()
            name = line[0]
            args = line[1:]
            #print(name, args)
            if name == "jnz":
                # Special case.
                reg, where = args
                reg = reg_to_int(reg)

                A = int(get_const("_" + str(i+1)))
                B = int(get_const(where))
                first = (B-A-1) % 2**16
                second = (A-2-first) % 2**16
                ins = "%{reg:02d}$c%1${first:05d}s%2$c%4$s%1${second:05d}s%3$hn"
                ins = ins.format(reg=reg, first=first, second=second)
            elif name == "jmp":
                tgt, = args
                tgt = get_const(tgt)
                ins = "%1${tgt}s%3$hn".format(tgt=tgt)
            else:
                next = int(get_const("_" + str(i+1)))
                compl = 2**16 - next
                ins = "%1${next:05d}s%3$hn%1${compl:05d}s"
                ins = ins.format(next=next, compl=compl)

                ap = ""
                if name == "mov":
                    dst, src = args
                    dst = dst_to_num(dst)
                    src = src_to_str(src)
                    ap = "%1${src}s%{dst}$hn".format(src=src, dst=dst)
                elif name == "add":
                    dst, src1, src2 = args
                    dst = dst_to_num(dst)
                    src1 = src_to_str(src1)
                    src2 = src_to_str(src2)
                    ap = "%1${src1}s%1${src2}s%{dst}$hn"
                    ap = ap.format(src1=src1, src2=src2, dst=dst)
                else:
                    print("Oops")
                    raise Exception("Unknown opcode: " + name)

                ins += ap

            #print("Asm:", ins)
            for j, c in enumerate(ins):
                code[pc+j] = c
            pc += len(ins) + 1 # For NUL

full = ""
for c in "".join(code).rstrip("\x00"):
    full += "\\x{:02x}".format(ord(c))

#print("Final code:")
#print(full)

scaffold = open(sys.argv[2]).read()
open(sys.argv[3], "w").write(scaffold.replace("PROG_HERE", full))
open(sys.argv[3] + ".map", "w").write("".join(
    "{:04x}".format(label_to_pc["_" + str(i)]) + ": " + assembly[i] + "\n"
        for i in range(len(assembly))))


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

import sys, string

lines = open(sys.argv[1]).readlines()
lines = [line.split(";")[0] for line in lines]
lines = [line.strip() for line in lines]
lines = [line for line in lines if line]
rom, lines = lines[0], lines[1:]

rom = [int(c) for c in rom.split()[1:]]

label_to_pc = {}
pc = 0
for line in lines:
    print("%03d: %s" % (pc, line))
    if ":" in line:
        label = line.strip(":")
        label_to_pc[label] = pc
    else:
        pc += 1

outfile = open(sys.argv[2], "w")

def out(s):
    outfile.write(s + "\n")

BITS = 8
# FLAG = "CTF{pr3pr0cess0r_pr0fe5sor}"
FLAG = "CTF{write_flag_here_please}"

CHARSET = string.ascii_letters + string.digits + "{}_"
def aschar(c):
    if c == "_":
        return "UNDERSCORE"
    if c == "{":
        return "LBRACE"
    if c == "}":
        return "RBRACE"
    return c

out("""// Copyright 2021 Google LLC
// 
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
// 
//     https://www.apache.org/licenses/LICENSE-2.0
// 
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.""")
out("#if __INCLUDE_LEVEL__ == 0")

out("// Please type the flag:")
for i in range(len(FLAG)):
    out("#define FLAG_%d CHAR_%s" % (i, aschar(FLAG[i])))
out("")
out("// No need to change anything below this line")

for c in CHARSET:
    out("#define CHAR_%s %d" % (aschar(c), ord(c)))

out("#warning \"Please wait a few seconds while your flag is validated.\"")

out("#define S 0")
for i, r in enumerate(rom):
    for j in range(8): # ROM is 8-bit
        out("#define ROM_{:08b}_{:d} {:d}".format(i, j, (rom[i]>>j) & 1))

for i in range(len(FLAG)):
    for j in range(8): # ROM is 8-bit
        out("#if FLAG_%d & (1<<%d)" % (i, j))
        out("#define ROM_{:08b}_{:d} 1".format(i + 128, j))
        out("#else")
        out("#define ROM_{:08b}_{:d} 0".format(i + 128, j))
        out("#endif")

out("#define _LD(x, y) ROM_ ## x ## _ ## y")
out("#define LD(x, y) _LD(x, y)")
out("#define _MA(l0, l1, l2, l3, l4, l5, l6, l7) l7 ## l6 ## l5 ## l4 ## l3 ## l2 ## l1 ## l0")
out("#define MA(l0, l1, l2, l3, l4, l5, l6, l7) _MA(l0, l1, l2, l3, l4, l5, l6, l7)")
out("#define l MA(l0, l1, l2, l3, l4, l5, l6, l7)")
out("#endif")

out("#if __INCLUDE_LEVEL__ > 12") # Max 2**12 steps


#out("#if 0")
pc = 0
for line in lines:
    if ":" in line:
        continue
    out("#if S == %d" % pc)
    #out("// %s" % line)
    out("#undef S")
    pc += 1
    out("#define S %d" % pc)
    words = line.split()
    opcode = words[0]
    args = words[1:]
    for i, arg in enumerate(args):
        arg = arg.strip().strip(",")
        if arg in label_to_pc:
            args[i] = (0, label_to_pc[arg]) # const
        else:
            try:
                n = int(arg, 0)
                args[i] = (0, n) # const
            except:
                args[i] = (1, arg) # Register
    print(opcode, args)
    def mov(a, b):
        if b[0] == 0:
            for i in range(BITS):
                if b[1] & (1<<i):
                    out("#define %s%d" % (a[1], i))
                else:
                    out("#undef %s%d" % (a[1], i))
        else:
            for i in range(BITS):
                out("#ifdef %s%d" % (b[1], i))
                out("#define %s%d" % (a[1], i))
                out("#else")
                out("#undef %s%d" % (a[1], i))
                out("#endif")

    def load(a, b):
        assert a[0] == 1
        assert b[0] == 1
        for i in range(8):
            out("#undef l%d" % i)
            out("#ifdef %s%d" % (b[1], i))
            out("#define l%d 1" % i)
            out("#else")
            out("#define l%d 0" % i)
            out("#endif")

        for i in range(8):
            out("#if LD(l, %d)" % i)
            out("#define %s%d" % (a[1], i))
            out("#else")
            out("#undef %s%d" % (a[1], i))
            out("#endif")

        for i in range(8, BITS):
            out("#undef %s%d" % (a[1], i))
            

    def add(a, b):
        assert a[0] == 1
        assert b[0] == 1
        out("#undef c")
        for i in range(BITS):
            # In four cases, we do nothing.
            out("#ifndef %s%d" % (a[1], i))

            out("#ifndef %s%d" % (b[1], i))
            out("#ifdef c")
            # 001 ABC
            out("#define %s%d" % (a[1], i))
            out("#undef c")
            out("#endif")
            out("#else")
            out("#ifndef c")
            # 010 ABC
            out("#define %s%d" % (a[1], i))
            out("#undef c")
            out("#endif")
            out("#endif")

            out("#else")

            out("#ifndef %s%d" % (b[1], i))
            out("#ifdef c")
            # 101 ABC
            out("#undef %s%d" % (a[1], i))
            out("#define c")
            out("#endif")
            out("#else")
            out("#ifndef c")
            # 110 ABC
            out("#undef %s%d" % (a[1], i))
            out("#define c")
            out("#endif")
            out("#endif")

            out("#endif")

    def xor(a, b):
        assert a[0] == 1
        assert b[0] == 1
        for i in range(BITS):
            out("#ifdef %s%d" % (b[1], i))

            out("#ifdef %s%d" % (a[1], i))
            out("#undef %s%d" % (a[1], i))
            out("#else")
            out("#define %s%d" % (a[1], i))
            out("#endif")

            out("#endif")

    def and_op(a, b):
        assert a[0] == 1
        assert b[0] == 1
        for i in range(BITS):
            out("#ifdef %s%d" % (a[1], i))
            out("#ifndef %s%d" % (b[1], i))
            out("#undef %s%d" % (a[1], i))
            out("#endif")
            out("#endif")

    def error(a):
        out("#error %s" % a[1])

    def or_op(a, b):
        assert a[0] == 1
        assert b[0] == 1
        for i in range(BITS):
            out("#ifndef %s%d" % (a[1], i))
            out("#ifdef %s%d" % (b[1], i))
            out("#define %s%d" % (a[1], i))
            out("#endif")
            out("#endif")

    def not_op(a):
        assert a[0] == 1
        for i in range(BITS):
            out("#ifdef %s%d" % (a[1], i))
            out("#undef %s%d" % (a[1], i))
            out("#else")
            out("#define %s%d" % (a[1], i))
            out("#endif")

    def ror(a):
        assert a[0] == 1
        for i in range(BITS):
            out("#ifdef %s%d" % (a[1], i+1))
            out("#define %s%d" % (a[1], i))
            out("#else")
            out("#undef %s%d" % (a[1], i))
            out("#endif")
            

    def jmp(dst):
        assert dst[0] == 0
        out("#undef S")
        out("#define S %d" % dst[1])

    def jl(dst, reg):
        assert dst[0] == 0
        out("#ifdef %s%d" % (reg[1], BITS-1))
        out("#undef S")
        out("#define S %d" % dst[1])
        out("#endif")

    def jz(dst, reg):
        assert dst[0] == 0
        for i in range(BITS):
            out("#ifndef %s%d" % (reg[1], i))
        out("#undef S")
        out("#define S %d" % dst[1])
        for i in range(BITS):
            out("#endif")


    if opcode == "mov":
        mov(args[0], args[1])
    elif opcode == "load":
        load(args[0], args[1])
    elif opcode == "add":
        add(args[0], args[1])
    elif opcode == "xor":
        xor(args[0], args[1])
    elif opcode == "and":
        and_op(args[0], args[1])
    elif opcode == "or":
        or_op(args[0], args[1])
    elif opcode == "not":
        not_op(args[0])
    elif opcode == "error":
        error(args[0])
    elif opcode == "jmp":
        jmp(args[0])
    elif opcode == "jl":
        jl(args[0], args[1])
    elif opcode == "jz":
        jz(args[0], args[1])
    elif opcode == "ror":
        ror(args[0])
    elif opcode == "halt":
        jmp((0, -1))
    else:
        assert False

    out("#endif") # S-state

out("#else") # include level
out("#if S != -1")
out("#include \"%s\"" % sys.argv[2])
out("#endif")
out("#if S != -1")
out("#include \"%s\"" % sys.argv[2])
out("#endif")
out("#endif")

out("#if __INCLUDE_LEVEL__ == 0")
out("#if S != -1")
out("#error \"Failed to execute program\"")
out("#endif")

"""
out("#define RES_A_0 0")
for i in range(BITS):
    out("#if defined(A%d)" % i)
    out("#define RES_A_%d RES_A_%d + %d" % (i+1, i, 1<<i))
    out("#else")
    out("#define RES_A_%d RES_A_%d" % (i+1, i))
    out("#endif")
"""

out("#include <stdio.h>")
out("int main() {")
# out("printf(\"%%x\\n\", RES_A_%d);" % BITS)
out("printf(\"Key valid. Enjoy your program!\\n\");")
out("printf(\"2+2 = %d\\n\", 2+2);")
out("}")
out("#endif")

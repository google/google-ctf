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
import random

random.seed(1337)

# python3 asm.py asm.s scaffold.cpp output.cpp

assembly = open(sys.argv[1]).readlines()
assembly = [line.strip() for line in assembly]
assembly = [line for line in assembly if line]




num_funs = 0
def name_gen():
    global num_funs
    num_funs += 1
    return "fun%04d" % num_funs


used_functions = set()
next_function = None
label_stack = []
codes = []
fwd = []
defs = []
for i, ln in enumerate(assembly):
    line = ln.split()
    #print(line, label_stack)
    code = ""
    fwd.append("void %s();" % next_function)
    next_function_ = name_gen()
    if line[0][0] == '#':
        defs.append(ln)
        continue
    if line[0].strip()[:2] == '//':
        continue
    if line[0] == "fun":
        next_function = line[1].split(":")[0].strip()
        continue
    elif line[0] == "loop":
        label_stack.append(("loop", name_gen(), next_function))
        assert ln[-1] == "{"
        fwd.append("class EndLp_%s {};" % next_function)
        code = "void %s() { try { %s(); } catch (const EndLp_%s&) { %s(); } }" % (
                next_function, next_function_, next_function, next_function)
        next_function = next_function_
    elif line[0] == "if":
        label_stack.append(("if", name_gen(), next_function))
        assert ln[-1] == "{"
        cond = ln.split("(", 1)[1].rsplit(")", 1)[0]
        code = "void %s() { if (%s) { %s(); } else { %s(); } }" % (
                next_function, cond, next_function_, label_stack[-1][1])
        next_function = next_function_
    elif line[0] == "call":
        which = line[1]
        code = "void %s() { try { %s(); } catch (const RetEx&) { %s(); }}" % (
                next_function, which, next_function_)
        next_function = next_function_
    elif line[0] == "break":
        j = -1
        while label_stack[j][0] != "loop":
            j -= 1
        code = "void %s() { /* break */ %s(); }" % (next_function, label_stack[j][1])
        next_function = next_function_
    elif line[0] == "return":
        code = "void %s() { throw RetEx{}; }" % next_function
        next_function = next_function_
    elif line[0] == "}":
        if label_stack[-1][0] == "loop":
            code = "void %s() { /* end lp */ throw EndLp_%s{}; }" % (
                    next_function, label_stack[-1][2])
        else:
            code = "void %s() { /* end if */ %s(); }" % (next_function, label_stack[-1][1])
        next_function = label_stack[-1][1]
        label_stack.pop()
    else:
        code = "void %s() { %s; %s(); }" % (next_function, ln, next_function_)
        next_function = next_function_

    #print(code)
    codes.append(code.strip())
    
random.shuffle(codes)
random.shuffle(defs)
random.shuffle(fwd)

print()
print()
print("\n".join(codes))
scaffold = open(sys.argv[2]).read()
open(sys.argv[3], "w").write(scaffold.replace("REPLACE_ME",
    "\n".join(defs + fwd + codes)))

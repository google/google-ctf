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



cnt = 0


# Example: v["is_add"]     == ~v["ins_7"] & ~v["ins_6"] & v["ins_5"] & v["ins_4"]

def new():
  global cnt
  cnt += 1
  return "var_%d" % cnt

def pvar(v):
  v = v.strip()
  pre = ''
  if v[0] == '~':
    pre = '~'
    v = v[1:]

  v = v.split('"')[1]
  return pre + v

def parse(line):
  line = line.split("==")
  if len(line) == 1:
    lhs = new()
  else:
    lhs = pvar(line[0])

  rhs = [pvar(p) for p in line[-1].split("&")]

  res = []
  for i in range(len(rhs)):
    if rhs[i][0] == '~':
      n = new()
      res.append([n, rhs[i][1:], rhs[i][1:]])
      rhs[i] = n

  while len(rhs) > 1:
    a = rhs.pop()
    b = rhs.pop()
    n = new()
    res.append([n, a, b])
    n2 = new()
    res.append([n2, n, n])
    rhs.append(n2)

  res[-1][0] = lhs
  res = [" ".join(r) for r in res]

  return res


lines = """
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
    """
lines = lines.strip().splitlines()
for line in lines:
  line = line.split("(")[1].split(")")[0]
  l = parse(line)
  for x in l:
    print(3)
    print(x)

print("---")

lines = """
        ~v["ins_0"] & ~v["ins_1"] & v["r0_7"],
        v["ins_0"] & ~v["ins_1"]  & v["r1_7"],
        ~v["ins_0"] & v["ins_1"]  & v["r2_7"],
        v["ins_0"] & v["ins_1"]   & v["r3_7"],
        """
lines = lines.strip().splitlines()
for i, line in enumerate(lines):
  line = line.split(",")[0]
  line = 'v["cond_%d"] == '%i + line
  l = parse(line)
  for x in l:
    print(3)
    print(x)


print("---")

lines = """
    constraints.append(v["is_or1n"]     == ~v["cond_0"] & ~v["cond_1"] & ~v["cond_2"] & ~v["cond_3"])
    constraints.append(v["is_or1"]     == ~v["is_or1n"])

    constraints.append(v["is_or2n"]     == ~v["is_load"] & ~v["is_store"])
    constraints.append(v["is_or2"]     == ~v["is_or2n"])

    constraints.append(v["is_and1"]     == v["is_or1"] & v["is_or2"])

    constraints.append(v["is_or3n"]     == ~v["is_rdtsc"] & ~v["is_putc"] & ~v["is_sysret"] & ~v["is_and1"])
    constraints.append(v["is_or3"]     == ~v["is_or3n"])

    constraints.append(v["security_exception"]     == ~v["is_root_now"] & v["is_or3"])
    """
lines = lines.strip().splitlines()
for line in lines:
  line = line.strip()
  if not line: continue
  line = line.split("(")[1].split(")")[0]
  l = parse(line)
  for x in l:
    print(3)
    print(x)










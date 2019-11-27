#!/usr/bin/python
# Copyright 2018 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http:#www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
import sys
import subprocess
import os

TARGET = ""

def whitespace_split(s):
  s = s.replace("\t", " ")
  return [x for x in s.split(" ") if x]

def read_program_header(fname, ep_name):
  output = subprocess.check_output([
    TARGET + "objdump",
    "-x",
    fname
  ]).splitlines()


  ph = []

  for i, ln in enumerate(output):
    if not ln.startswith("Program Header:"):
      continue

    j = i + 1
    while True:
      ln = output[j].strip()
      if not ln:
        break

      ln1 = whitespace_split(ln)
      j += 1
      ln2 = whitespace_split(output[j].strip())
      j += 1

      if ln1[0] != "LOAD":
        print "skipping", ln1[0]
        continue

      ph.append({
        "off": int(ln1[2], 16),
        "vaddr": int(ln1[4], 16),
        "filesz": int(ln2[1], 16),
        "memsz": int(ln2[3], 16),
      })
    break

  ep = None
  for ln in output:
    if ep_name in ln:
      ep = int(whitespace_split(ln)[0], 16)

  return ph, ep

ph, ep = read_program_header("checker", "ep_checker")

d = open("gold.py.template").read()

d = d.replace("VA_0_TEMPLATE", "0x%x" % ph[0]["vaddr"])
d = d.replace("MEMSZ_0_TEMPLATE", "0x%x" % ph[0]["memsz"])
d = d.replace("OFF_0_TEMPLATE", "0x%x" % ph[0]["off"])
d = d.replace("FILESZ_0_TEMPLATE", "0x%x" % ph[0]["filesz"])

d = d.replace("VA_1_TEMPLATE", "0x%x" % ph[1]["vaddr"])
d = d.replace("MEMSZ_1_TEMPLATE", "0x%x" % ph[1]["memsz"])
d = d.replace("OFF_1_TEMPLATE", "0x%x" % ph[1]["off"])
d = d.replace("FILESZ_1_TEMPLATE", "0x%x" % ph[1]["filesz"])

d = d.replace("EP_TEMPLATE", "0x%x" % ep)

d = d.splitlines()


rv = bytearray(open("checker", "rb").read().encode('zlib'))

o = []
for ln in d:
  #if ln.strip().startswith('#'):
  #  continue
  if not ln.strip():
    continue
  if ln == '"PROG_TEMPLATE"':
    txt = "prog = '"
    txt += ''.join(["\\x%.2x" % x for x in rv])
    txt += "'.decode('zlib')"
    o.append(txt)
    continue

  o.append(ln)

out = '\n'.join(o)
#out = '# -*- coding: rot13 -*-\n' + out.encode('rot13')
f = open("gold.py", "w")
f.write(out)
f.close()



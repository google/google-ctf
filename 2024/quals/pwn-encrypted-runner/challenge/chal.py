# Copyright 2024 Google LLC
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
import subprocess
import os


def menu():
  print("What do you want to do?")
  print("- encrypt command (e.g. 'encrypt echo test')")
  print("- run command (e.g. 'run fefed6ce5359d0e886090575b2f1e0c7')")
  print("- exit")

print("Welcome to encrypted command runner.")

whitelist = {
    "date": None,
    "echo": "[\\w. ]+",
    "ls": "[/\\w]+",
}

whiteset = set(cmd.encode() for cmd in whitelist)

def helper(cmd, data):
  if cmd == "encrypt":
    data = [ord(c) for c in data]
  else:
    data = list(bytes.fromhex(data))

  while len(data) < 16:
    data.append(0)

  # 16 bytes should be enough for everybody...
  inp = cmd + " " + " ".join("%02x" % c for c in data[:16])
  res = subprocess.check_output("./aes", input = inp.encode())
  return bytes.fromhex(res.decode())

counter = 0
while True:
  counter += 1
  if counter > 100:
    print("All right, I think that's enough for now.")
    break

  menu()
  line = input()
  if line.strip() == "exit":
    print("Bye.")
    break

  what, rest = line.split(" ", 1)
  if what == "encrypt":
    cmd = rest.split(" ")[0]
    if cmd not in whitelist:
      print("I won't encrypt that. ('%s' not in whitelist)" % cmd)
      continue
    regex = [cmd]
    if whitelist[cmd]:
      regex.append(whitelist[cmd])
    regex = " ".join(regex)
    match = re.fullmatch(regex, rest)
    if not match:
      print("I won't encrypt that. ('%s' does not match '%s')" % (rest, regex))
      continue
    res = helper("encrypt", rest)
    print("Encrypted command:", res.hex())
  elif what == "run":
    command = helper("decrypt", rest).rstrip(b"\x00")
    cmd = command.split(b" ")[0]
    if cmd not in whiteset:
      print("I won't run that. (%s not in whitelist)" % cmd)
      continue
    res = subprocess.run(command, shell = True, stdout = subprocess.PIPE,
                         stderr = subprocess.STDOUT, check = False)
    print("Output:", res.stdout.decode())
  else:
    print("What?")


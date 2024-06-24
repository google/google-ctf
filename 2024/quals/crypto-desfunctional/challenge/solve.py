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





class RemoteChall:
    def __init__(self, host_port=None):
        if host_port:
            self.rem = remote(*host_port)
        else:
            self.rem = process("python3 chall.py", shell=True)
        self.rem.recvuntil(b"Get the flag\n")

    def get_challenge(self):
        self.rem.sendline(b"1")
        data = self.rem.recvuntil(b"Get the flag\n")
        hex_data=re.search(b'([0-9a-f]+)\n', data)[1]
        return bytes.fromhex(hex_data.decode())

    def decrypt(self, pt):
        self.rem.sendline(b"2")
        self.rem.sendline(pt.hex().encode())
        # breakpoint()
        data = self.rem.recvuntil(b"Get the flag\n")
        hex_data=re.search(b'([0-9a-f]+)\n', data)[1]
        # breakpoint()
        return bytes.fromhex(hex_data.decode())

    def get_flag(self, guess):
        self.rem.sendline(b"3")
        self.rem.sendline(guess.hex().encode())
        print(self.rem.recvall().decode())


from collections import Counter

rem = RemoteChall(('localhost', 1337))
chal_enc = rem.get_challenge()
num_blocks = len(chal_enc)//8

seen = [Counter() for i in range(num_blocks)]

for k in range(2):
    enc_not = bytearray(chal_enc)
    for i in range(k, num_blocks, 2):
        for j in range(8):
            enc_not[i * 8 + j] ^= 255

    for i in range(64):
        dd = bytearray(rem.decrypt(enc_not))
        for i in range(k, num_blocks, 2):
            chunk = bytes(dd[i * 8 + j] ^ 255 for j in range(8))
            seen[i][chunk] += 1

chall_dec = b''.join(i.most_common(1)[0][0] for i in seen)
rem.get_flag(chall_dec)


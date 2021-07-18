#!/usr/bin/env python3

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

import subprocess
from Crypto.Cipher import AES

#key = bytes.fromhex('00'*16)
key = bytes([0x1d, 0x5, 0xef, 0xe8, 0x63, 0xc3, 0xd9, 0x92, 0xa8, 0xf1, 0x7b, 0xce, 0x93, 0x47, 0x59, 0x5b])
iv = b'X'*16

message1 = 'This is a super secret message that we will encrypt with the special device'
message2 = 'This message is testing the padding by an even multiple of 0x10!'
flag_message = 'This is agent 1337 reporting back to base. I have completed the mission but I am being pursued by enemy operatives. They are closing in on me and I suspect the safe-house has been compromised. I managed to steal the codes to the mainframe and sending it over now: CTF{HAVE_YOU_EVER_SEEN_A_Z80_CPU_WITH_AN_AES_PERIPHERAL}. If you do not hear from me again, assume the worst. Agent out!'

def encrypt(plaintext):
    p = subprocess.Popen(['./emulator', 'firmware.ihx', '1000000'], stdin=subprocess.PIPE, stdout=subprocess.PIPE)
    ciphertext, _ = p.communicate((plaintext+'\n').encode('ascii'))
    p.wait()
    assert len(ciphertext) % AES.block_size == 0
    return ciphertext

def decrypt(ciphertext, key, iv):
    aes = AES.new(key, mode=AES.MODE_CBC, IV=iv)
    plaintext = aes.decrypt(ciphertext)
    #print(plaintext)
    plaintext = plaintext[:-plaintext[-1]]
    return plaintext

def verify(message):
    c = encrypt(message)
    m = decrypt(c, key, iv)
    assert m.decode('ascii') == message


verify(message1)
verify(message2)
chall_ciphertext = encrypt(flag_message)
with open('captured_transmission.dat', 'wb') as fout:
    fout.write(chall_ciphertext)

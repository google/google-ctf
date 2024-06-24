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
import sys

elf = ELF(sys.argv[1])
sec_bytes = elf.section("encrypted")
sec = elf.get_section_by_name("encrypted")

off = sec.header.sh_offset

perm = [222, 182, 104, 196, 208, 215, 152, 142, 21, 176, 158, 117, 219, 15, 113, 251, 133, 124, 47, 45, 96, 255, 242, 190, 98, 43, 161, 149, 153, 209, 91, 13, 165, 199, 58, 53, 214, 48, 64, 18, 228, 73, 61, 246, 107, 201, 108, 178, 8, 71, 26, 105, 52, 36, 83, 88, 54, 131, 240, 187, 197, 204, 32, 3, 162, 76, 202, 227, 128, 2, 211, 231, 66, 23, 17, 248, 229, 12, 186, 50, 220, 27, 112, 233, 192, 221, 217, 170, 141, 134, 213, 40, 85, 177, 84, 163, 33, 25, 132, 75, 239, 140, 212, 174, 157, 39, 123, 106, 42, 44, 22, 31, 146, 65, 164, 102, 19, 223, 173, 238, 236, 147, 115, 94, 156, 138, 160, 185, 56, 89, 62, 57, 7, 95, 184, 241, 210, 126, 232, 87, 169, 74, 130, 68, 5, 188, 92, 168, 237, 172, 4, 67, 60, 191, 99, 139, 203, 167, 20, 72, 119, 125, 63, 116, 226, 118, 247, 207, 175, 250, 159, 148, 120, 103, 16, 235, 6, 195, 49, 218, 253, 80, 14, 225, 154, 59, 46, 86, 69, 38, 166, 249, 244, 194, 234, 82, 245, 110, 129, 206, 41, 198, 151, 111, 93, 37, 55, 51, 143, 78, 79, 97, 144, 252, 81, 9, 136, 155, 90, 145, 122, 137, 34, 135, 24, 1, 10, 109, 70, 205, 171, 121, 30, 29, 179, 100, 254, 127, 243, 11, 150, 200, 181, 189, 101, 180, 193, 216, 77, 114, 230, 183, 28, 224, 0, 35]

"""
de b6 68 c4 d0 d7 98 8e 15 b0 9e 75 db 0f 71 fb 85 7c 2f 2d 60 ff f2 be 62 2b a1 95 99 d1 5b 0d a5 c7 3a 35 d6 30 40 12 e4 49 3d f6 6b c9 6c b2 08 47 1a 69 34 24 53 58 36 83 f0 bb c5 cc 20 03 a2 4c ca e3 80 02 d3 e7 42 17 11 f8 e5 0c ba 32 dc 1b 70 e9 c0 dd d9 aa 8d 86 d5 28 55 b1 54 a3 21 19 84 4b ef 8c d4 ae 9d 27 7b 6a 2a 2c 16 1f 92 41 a4 66 13 df ad ee ec 93 73 5e 9c 8a a0 b9 38 59 3e 39 07 5f b8 f1 d2 7e e8 57 a9 4a 82 44 05 bc 5c a8 ed ac 04 43 3c bf 63 8b cb a7 14 48 77 7d 3f 74 e2 76 f7 cf af fa 9f 94 78 67 10 eb 06 c3 31 da fd 50 0e e1 9a 3b 2e 56 45 26 a6 f9 f4 c2 ea 52 f5 6e 81 ce 29 c6 97 6f 5d 25 37 33 8f 4e 4f 61 90 fc 51 09 88 9b 5a 91 7a 89 22 87 18 01 0a 6d 46 cd ab 79 1e 1d b3 64 fe 7f f3 0b 96 c8 b5 bd 65 b4 c1 d8 4d 72 e6 b7 1c e0 00 23
"""

new_bytes = []
for b in sec_bytes:
  new_bytes.append(perm[b])

old_file = open(sys.argv[1], "rb").read()

new_file = old_file[:off] + bytes(new_bytes) + old_file[off + len(sec_bytes):]

open("decrypted", "wb").write(new_file)

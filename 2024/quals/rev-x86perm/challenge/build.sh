#!/bin/bash
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

gcc src.c -o binary
objdump -D -Mintel binary -j encrypted > objdump_before
python3 encrypt.py binary
objdump -D -Mintel binary -j encrypted > objdump_after
#strip binary

# test:

echo 'de b6 68 c4 d0 d7 98 8e 15 b0 9e 75 db 0f 71 fb 85 7c 2f 2d 60 ff f2 be 62 2b a1 95 99 d1 5b 0d a5 c7 3a 35 d6 30 40 12 e4 49 3d f6 6b c9 6c b2 08 47 1a 69 34 24 53 58 36 83 f0 bb c5 cc 20 03 a2 4c ca e3 80 02 d3 e7 42 17 11 f8 e5 0c ba 32 dc 1b 70 e9 c0 dd d9 aa 8d 86 d5 28 55 b1 54 a3 21 19 84 4b ef 8c d4 ae 9d 27 7b 6a 2a 2c 16 1f 92 41 a4 66 13 df ad ee ec 93 73 5e 9c 8a a0 b9 38 59 3e 39 07 5f b8 f1 d2 7e e8 57 a9 4a 82 44 05 bc 5c a8 ed ac 04 43 3c bf 63 8b cb a7 14 48 77 7d 3f 74 e2 76 f7 cf af fa 9f 94 78 67 10 eb 06 c3 31 da fd 50 0e e1 9a 3b 2e 56 45 26 a6 f9 f4 c2 ea 52 f5 6e 81 ce 29 c6 97 6f 5d 25 37 33 8f 4e 4f 61 90 fc 51 09 88 9b 5a 91 7a 89 22 87 18 01 0a 6d 46 cd ab 79 1e 1d b3 64 fe 7f f3 0b 96 c8 b5 bd 65 b4 c1 d8 4d 72 e6 b7 1c e0 00 23


' > /tmp/input

cat /tmp/input - | ./binary


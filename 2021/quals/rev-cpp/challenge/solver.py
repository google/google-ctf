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


rom = "187 85 171 197 185 157 201 105 187 55 217 205 33 179 207 207 159 9 181 61 235 127 87 161 235 135 103 35 23 37 209 27 8 100 100 53 145 100 231 160 6 170 221 117 23 157 109 92 94 25 253 233 12 249 180 131 134 34 66 30 87 161 40 98 250 123 27 186 30 180 179 88 198 243 140 144 59 186 25 110 206 223 241 37 141 64 128 112 224 77 28"
rom = [int(c) for c in rom.split()]

def fib(n):
    a, b = 0, 1
    for i in range(n):
        a, b = b, a+b
    return a

multipliers, xors, exp = rom[:32], rom[32:64], rom[64:]
pref = 0
flag = ""
for i, e in enumerate(exp):
    this = e - pref
    pref = e

    this += 256
    this &= 255

    this ^= xors[i]
    this -= fib(i+1)
    this += 256
    this &= 255
    this *= pow(multipliers[i], -1, 256)
    this &= 255
    flag += chr(this)
print(flag)

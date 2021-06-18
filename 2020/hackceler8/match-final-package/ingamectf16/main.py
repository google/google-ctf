#!/usr/bin/python3
# Copyright 2020 Google LLC
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
with open('./flag') as f:
    flag = f.read().strip()

print('''
  ________                                         .__                 ______
 /  _____/ __ __   ____   ______ ______ ____  ____ |  |   ___________ /  __  \ 
/   \  ___|  |  \_/ __ \ /  ___//  ___// ___\/ __ \|  | _/ __ \_  __ \>      <
\    \_\  \  |  /\  ___/ \___ \ \___ \\\\  \__\  ___/|  |_\  ___/|  | \/   --   \ 
 \______  /____/  \___  >____  >____  >\___  >___  >____/\___  >__|  \______  /
        \/            \/     \/     \/     \/    \/          \/             \/ 

        — Can you guess the flag?
''')

guess = ''
while guess != flag:
    guess = input('> ')
    if len(guess) != len(flag):
        print('Invalid length.')
        continue
    out = ''
    for j,k in zip(guess, flag):
        if j == k:
            out += j
        elif j in flag:
            out += '*'
        else:
            out += '.'
    print(out)
print('%s is the correct flag.' % flag)


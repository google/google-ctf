#!/usr/bin/env python3

# Copyright 2019 Google LLC
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

import os
import sys
import pty
import subprocess
import termios
import signal
import threading

print(r'''
_________________________________.__
\_   _____/\_   _____/\_   _____/|__| ____    ____
 |    __)_  |    __)   |    __)  |  |/    \  / ___\
 |        \ |     \    |     \   |  |   |  \/ /_/  >
/_______  / \___  /    \___  /   |__|___|  /\___  /
        \/      \/         \/            \//_____/
        GoogleCTF 2019  - isn't this fun?
'''.strip())


class Reader(threading.Thread):
    def __init__(self, input, output):
        super(Reader, self).__init__()
        self.input = input
        self.output = output

    def run(self):
        try:
            b = b''
            while b'>>> >>> >>> >>> ... ... >>> ' not in b:
              b += os.read(self.input, 1)

            while True:
                c = os.read(self.input, 1)
                if c == '':
                    break
                os.write(self.output, c)
        except:
            pass


parent_pty, child_pty = pty.openpty()
p = subprocess.Popen(['python3'], stdin=child_pty, stdout=child_pty, stderr=subprocess.DEVNULL)
os.close(child_pty)

os.write(parent_pty, b'''
forbidden  = [input, print, chr, ord, type, locals, compile, repr, globals]
forbidden += [setattr, memoryview, exec, __import__, eval ]
for f in forbidden:
  delattr(__builtins__, f.__name__)

del forbidden
''')

new = termios.tcgetattr(parent_pty)
new[3] &= ~termios.ECHO
termios.tcsetattr(parent_pty, termios.TCSANOW, new)

def handle_alarm(meh, meh2):
    print('meh')
    p.kill()
    sys.exit(0)


signal.signal(signal.SIGALRM, handle_alarm)
signal.alarm(15)

Reader(parent_pty, sys.stdout.fileno()).start()

i = 0
try:
  while True:
    c = os.read(0, 1)
    i += 1

    if i > 2048:
        print('too much data')
        p.kill()
        break

    if c == b'':
        os.close(parent_pty)
        break

    if c not in b' !"#$%&\'()*+,-./:;<=>?@f[\\]^_`{|}~\n\r':
        continue

    os.write(parent_pty, c)
except:
    p.kill()
finally:
    p.wait()

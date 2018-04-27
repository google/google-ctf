#!/usr/bin/python
#
# Copyright 2018 Google LLC
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

import sys

def crc_82_darc(s):
    r = 0
    for c in s:
        r ^= ord(c)
        for _ in range(8):
            if r & 1:
                r ^= 0x441011401440444018861
            r >>= 1
    return r

def main():
    sys.stdout.write("Give me some data: ")
    sys.stdout.flush()
    data = sys.stdin.readline().strip()
    print

    if not (len(data) == 82):
        print "Check failed.\nExpected:"
        print "    len(data) == 82"
        print "Was:"
        print "    %r" % len(data)
        return

    if not (set(data) <= set("01")):
        print "Check failed.\nExpected: "
        print "    set(data) <= set(\"01\")"
        print "Was:"
        print "    %r" % set(data)
        return

    if not (crc_82_darc(data) == int(data, 2)):
        print "Check failed.\nExpected: "
        print "    crc_82_darc(data) == int(data, 2)"
        print "Was:"
        print "    %r" % crc_82_darc(data)
        print "    %r" % int(data, 2)
        return

    with open('flag.txt') as fd:
        print fd.read()

main()

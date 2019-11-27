#!/usr/bin/python
# Copyright 2018 Google LLC
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
d = bytearray(open("checker.flat", "rb").read())
o = ','.join(["0x%.2x" % x for x in d])

f = open("checker_as_mem.c", "w");
f.write("uint8_t mem[] = {")
f.write(o)
f.write("};\n")

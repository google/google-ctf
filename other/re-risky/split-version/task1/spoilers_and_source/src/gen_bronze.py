#!/usr/bin/python
# Copyright 2018 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http:#www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
FLAG = 'flag{88%Copper+12%Tin}'
flag = ''.join([chr(ch ^ 0xa5) for ch in bytearray(FLAG)])

d = open("bronze.py.template").read()

out = d.replace('FLAG_TEMPLATE', flag.encode('string-escape'))

f = open("bronze.py", "w")
f.write(out)
f.close()



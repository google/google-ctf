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

__author__      = "Ian Eldred Pudney"

import sys

data = sys.stdin.read()
print "#include \"xorstr.h\""
print "#include \"string.h\""
print "#include <string>"

split_data = [data[i:i+57] for i in range(0, len(data), 57)]

print "std::string " + sys.argv[1] + "() {"
print "  std::string ret;"

for line in split_data:
  print "  ret += xorstr(R\"EOF(" + line + ")EOF\").crypt_get();"
print "  return ret;"
print "}"

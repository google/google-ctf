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

import sys

bin_filename = sys.argv[1].encode("utf-8")
sentinel = sys.argv[2].encode("utf-8")
replacement_filename = sys.argv[3].encode("utf-8")

with open(bin_filename, 'rb') as f:
  data = f.read()

idx = data.find(sentinel)
if idx == -1:
  sys.stderr.write("Failed to find sentinel %s" % sentinel)
  sys.exit(-1)

with open(replacement_filename, 'rb') as f:
  replacement = f.read()

data_list = [c for c in data]
repl_list = [c for c in replacement]

if len(data_list[idx:idx+len(replacement)]) != len(repl_list):
  sys.stderr.write("Length mismatch between region and replacement")
  sys.exit(-1)

data_list[idx:idx+len(replacement)] = repl_list
new_data = bytes(data_list)

if len(data) != len(new_data):
  sys.stderr.write("Length mismatch between old and new data")
  sys.exit(-1)

with open(bin_filename, 'wb') as f:
  f.write(new_data)


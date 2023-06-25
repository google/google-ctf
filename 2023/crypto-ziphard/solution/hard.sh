#!/bin/sh
# Copyright 2023 Google LLC

# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at

#     https://www.apache.org/licenses/LICENSE-2.0

# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# Figure out the length of the flag plaintext
first_offset=`unzip -Z -v hard.zip flag.txt | awk '/uncompressed size/ { print strtonum($3)-1 }'`

# Figure out the crc of junk.dat
second_crc=`unzip -Z -v hard.zip junk.dat | awk '/CRC/ { print substr($5,1,8) }'`

# Figure out offset in hard.zip where junk.dat ciphertext (including nonce) begins
second_offset=`unzip -Z -v hard.zip junk.dat | awk '/offset of local header from start of archive:/ {
	offset = $9
}
/length of filename:/ {
	print offset + 30 + $4
}'`


# generate second_ciphertext
dd if=hard.zip of=second_ciphertext bs=1 skip=$second_offset count=16

# generate second_plaintext
./crackcrc $second_crc 0 ffffffff

OMP_NUM_THREADS=8 ./bkcrack-patched -c flag.txt -C hard.zip -x 0 efbbbf4354467b -x $first_offset 7d


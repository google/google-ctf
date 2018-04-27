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

import hashlib
import struct
import zlib

with open('classes.dex', 'rb') as f:
    dex = f.read()

dex_list = map(ord, dex)

# Patch out F.cc()
start_idx = 0x720
size = 0x90
end_idx = start_idx + size
insns = map(ord, dex[start_idx:end_idx])
print 'F.cc():', [x ^ 0x5a for x in insns], len(insns)

dex_list[start_idx:end_idx] = [14] * size

"""
# Trick Androguard by switching the order of TYPE_STRING_DATA_ITEM
# and TYPE_ENCODED_ARRAY_ITEM in map_list
map_off, = struct.unpack("=I", dex[0x34:0x38])
map_off += struct.calcsize("=I")

entry_size = struct.calcsize("=HHII")
string_data_ptr = map_off + 11 * entry_size
encoded_array_ptr = map_off  + 14 * entry_size

dex_list[string_data_ptr:string_data_ptr+entry_size] = map(ord, 
    dex[encoded_array_ptr:encoded_array_ptr+entry_size])
dex_list[encoded_array_ptr:encoded_array_ptr+entry_size] = map(ord, 
    dex[string_data_ptr:string_data_ptr+entry_size])
"""

# Fix checksums
dex_out = ''.join(map(chr, dex_list))
sha1 = map(ord, hashlib.sha1(dex_out[0x20:]).digest())
dex_list[0xC:0x20] = sha1

dex_out = ''.join(map(chr, dex_list))
crc = map(ord, struct.pack("=I", (zlib.adler32(dex_out[0xC:]) & 0xFFFFFFFF)))
dex_list[0x8:0xC] = crc

dex_out = ''.join(map(chr, dex_list))
with open('output.dex', 'wb') as f:
    f.write(dex_out)
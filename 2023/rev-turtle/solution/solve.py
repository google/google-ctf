# Copyright 2023 Google LLC
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


from PIL import Image

im = Image.open("m.png")
pix = im.load()
w, h = im.size

mem = []

k = 0
for i in range(h):
    for j in range(w):
        mem.append(pix[j,i][0])

print(mem[95:115])
flag = [' ']*30

cnt = 95
for tgt in range(43, 123):
    print(tgt, chr(tgt))
    left = 0
    flaglen = 30
    while True:
        print("left", left, "len", flaglen, "mem", mem[cnt], cnt)
        if flaglen == 0:
            assert mem[cnt] == 4
            cnt += 1
            break
        newindex = (flaglen-1) // 2
        print("  ", newindex)
        if mem[cnt] == 1:
            # tgt < flag[newindex]
            flaglen = newindex
            cnt += 1
        elif mem[cnt] == 2:
            left += newindex + 1
            flaglen -= newindex + 1
            cnt += 1
        else:
            assert mem[cnt] == 3
            flag[left+newindex] = chr(tgt)
            print("NICE!!!", left+newindex, chr(tgt))
            cnt += 1
            break


print("".join(flag))

perm = mem[65:95]
print(perm)

permuted = [' '] * 30
for i, p in enumerate(perm):
    permuted[i] = flag[p]

print("".join(permuted))

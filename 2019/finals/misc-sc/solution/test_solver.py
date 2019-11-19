#/usr/bin/python3

# Copyright 2019 Google LLC
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

#
# https://liquipedia.net/starcraft/Storm_Packets
# https://github.com/HearthSim/pyreplib/blob/master/doc/replay_format.txt
# tshark -r only_ipx.pcapng -e "data.data" -Tfields > sc.txt

bitmap = bytearray(256 * 256)

with open("sc.txt") as f:
  lines = f.read().splitlines()

  for ln in lines:
    data = bytearray(bytes.fromhex(ln))
    if len(data) < 20:
      continue
    if data[12] != 0x37:  # ?game packet?
      continue

    if data[19] != 0x0c:  # Build a building
      continue

    building_type = data[20]
    pos_x = data[21] | (data[22] << 8)
    pos_y = data[23] | (data[24] << 8)
    building_id = data[25]

    if building_id != 0x9c: # Is it a pylon?
      continue

    print("t=%.2x (%i, %i) id=%.2x " % (building_type, pos_x, pos_y, building_id))
    bitmap[pos_x + pos_y * 256] = 255

with open("dump_256_256_8bpp.raw", "wb") as f:
  f.write(bitmap)


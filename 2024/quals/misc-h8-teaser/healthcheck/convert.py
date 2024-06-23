# Copyright 2024 Google LLC
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

import struct
import json

with open("flag1-solution.txt") as f:
  while True:
    size_bytes = f.read(4)
    if len(size_bytes) != 4:
      break
    size = struct.unpack(">I", bytes(size_bytes, "utf-8"))[0]
    ret = f.read(size)
    assert len(ret) == size, "Unexpected packet length"
    keys = json.loads(ret).get("keys", [])
    print(" ".join(["%02x"%a for a in keys]))

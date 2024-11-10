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

def read_str(f) -> str:
  result = b''
  while True:
    b = f.read(1)
    if b == b'\0':
      break
    result += b
  return result.decode()

class Tileset:
  def __init__(self):
    self.tw = None
    self.th = None
    self.w = None
    self.h = None
    self.image = None
    self.anims = []

  def load(self, tileset_file):
    with open(tileset_file, "rb") as tf:
      self.tw = struct.unpack("<H", tf.read(2))[0]
      self.th = struct.unpack("<H", tf.read(2))[0]
      self.w = struct.unpack("<H", tf.read(2))[0]
      self.h = struct.unpack("<H", tf.read(2))[0]
      self.image = read_str(tf)
      self.anims = []
      for i in range(struct.unpack("<H", tf.read(2))[0]):
        anim = {"name": read_str(tf), "loop": struct.unpack("?", tf.read(1))[0]}
        frames = []
        for j in range(struct.unpack("<H", tf.read(2))[0]):
          frames.append({
            "id": struct.unpack("<H", tf.read(2))[0],
            "duration": struct.unpack("<H", tf.read(2))[0],
          })
        anim["frames"] = frames
        self.anims.append(anim)

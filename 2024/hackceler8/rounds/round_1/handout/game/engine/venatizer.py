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
import logging
from game.components.wall import Wall

class FakeSize:

  def __init__(self, width, height):
    self.width = width
    self.height = height


class FakeCoord:

  def __init__(self, x, y):
    self.x = x
    self.y = y


class Venatizer:

  def __init__(self, game):
    self.game = game
    self.map = self.game.tiled_map
    self.max_x = self.map.size.width
    self.max_y = self.map.size.height

    self.counter = 0
    # How many tiles per second are being nuked
    self.advancement_speed = 5
    self.wall_width = self.map.tile_size.width

  def tick(self):
    w = Wall(
      coords=FakeCoord(self.counter // self.advancement_speed * self.wall_width,
                       10000),
             x1=self.counter // self.advancement_speed * self.wall_width,
      x2=self.counter // self.advancement_speed * self.wall_width + self.wall_width,
      y1=0,
      y2=10000,
             name="killawall")

    self.game.objects.append(w)
    self.counter += 1
    return

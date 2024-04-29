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

import arcade
from engine import generics
from engine import hitbox


class Portal(generics.GenericObject):
    def __init__(self, coords, size, name, dest, x_speed=None, y_speed=None, usage_limit=None):
        self.perimeter = [
            hitbox.Point(coords.x, coords.y),
            hitbox.Point(coords.x + size.width, coords.y),
            hitbox.Point(coords.x + size.width, coords.y - size.height),
            hitbox.Point(coords.x, coords.y - size.height),
        ]
        super().__init__(coords, "Portal", None, self.perimeter)
        self.blocking = False
        self.name = name
        self.dest = dest
        self.size = size
        self.x_speed = x_speed
        self.y_speed = y_speed
        self.usage_count = 0
        self.usage_limit = usage_limit

    def reset(self):
        super().reset()
        self.usage_count = 0

    def draw(self):
        r = self.size.width // 2
        arcade.draw_circle_outline(self.x + r, self.y - r, r*1.2, arcade.csscolor.BLUE, border_width=5)

    def deduct_usage(self):
        if self.usage_limit is None:
            return True

        if self.usage_count >= self.usage_limit:
            return False

        self.usage_count += 1
        return True

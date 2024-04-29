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

from engine import generics
from engine import hitbox


class Soul(generics.GenericObject):
    def __init__(self, coords, speed_x, speed_y, base_damage=10):
        self.perimeter = [
            hitbox.Point(coords.x - 7, coords.y + 10),
            hitbox.Point(coords.x + 7, coords.y + 10),
            hitbox.Point(coords.x + 7, coords.y - 10),
            hitbox.Point(coords.x - 7, coords.y - 10),
        ]
        super().__init__(coords, nametype="Soul",
                         tileset_path="resources/objects/soul.tmx",
                         outline=self.perimeter)
        self.set_speed(speed_x, speed_y)
        self.base_damage = base_damage
        self.enable_moving_physics = True
        self.x_sticky = True

    def check_oob(self):
        if self.x < -10000 or self.x > 10000:
            return True
        if self.y < -10000 or self.y > 10000:
            return True

        return False

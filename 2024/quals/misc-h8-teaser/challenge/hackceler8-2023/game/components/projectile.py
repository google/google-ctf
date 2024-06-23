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

import constants
from engine import generics
import engine.hitbox as hitbox


class Projectile(generics.GenericObject):
    def __init__(self, coords, speed_x, speed_y, origin, damage_algo="constant",
                 damage_type="single", base_damage=10, scale=1):
        outline = [
            hitbox.Point(coords.x - 7 * scale, coords.y - 12 * scale),
            hitbox.Point(coords.x + 7 * scale, coords.y - 12 * scale),
            hitbox.Point(coords.x + 7 * scale, coords.y + 12 * scale),
            hitbox.Point(coords.x - 7 * scale, coords.y + 12 * scale),
        ]
        super().__init__(coords, nametype="Projectile",
                         tileset_path="resources/objects/fire.tmx", outline=outline)
        self.affected_by_gravity = False
        self.sprite.scale = scale
        self.set_speed(speed_x, speed_y)
        self.origin = origin
        self.damage_algo = damage_algo
        self.damage_type = damage_type
        self.base_damage = base_damage

    def check_oob(self, player):
        if abs(player.x - self.x) > constants.SCREEN_WIDTH:
            return True
        if abs(player.y - self.y) > constants.SCREEN_HEIGHT:
            return True

        return False

    def update_position(self):
        self.move(self.x_speed, self.y_speed)

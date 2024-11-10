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

from game import constants
from game.engine import generics
import game.engine.hitbox as hitbox


class Projectile(generics.GenericObject):

    def __init__(
            self,
            coords,
            speed_x,
            speed_y,
            origin,
            base_damage=10,
            scale=1,
            img="resources/objects/bullet.png",
            weapon=None,
    ):
        rect = hitbox.Rectangle(
            coords.x - 8 * scale, coords.x + 8 * scale,
            coords.y - 8 * scale, coords.y + 8 * scale
        )
        super().__init__(
            coords,
            nametype="Projectile",
            tileset_path=img,
            rect=rect,
        )
        self.sprite.scale = scale
        self.set_speed(speed_x, speed_y)
        self.origin = origin
        self.base_damage = base_damage
        self.weapon = weapon

    def check_oob(self, player):
        if abs(player.x - self.x) > constants.SCREEN_WIDTH:
            return True
        if abs(player.y - self.y) > constants.SCREEN_HEIGHT:
            return True

        return False

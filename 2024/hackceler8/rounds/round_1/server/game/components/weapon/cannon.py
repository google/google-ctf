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
import itertools
from typing import Iterable

import game.engine.hitbox as hitbox
from game.engine import gfx
from game.components.weapon.weapon import Weapon


class Cannon(Weapon):
    def __init__(self, coords, name):
        rect = hitbox.Rectangle(coords.x - 16, coords.x + 16, coords.y - 16, coords.y + 16)
        super().__init__(
            coords=coords,
            name=name,
            display_name="Cannon",
            tileset_path="resources/objects/weapons/cannon.png",
            rect=rect,
        )

        self.last_tick = 0
        self.charging = None
        self.charge_amount = 0

    def get_draw_info(self) -> gfx.IterableParams:
        ret = [super().get_draw_info()]
        if not self.charging:
            return ret
        radius = max(10, (270 - self.charge_amount) * 0.5)
        if self.charge_amount < 180:
            color = (255,255,255,255)
        else:
            color = (255,165,0,255)
        return [ret, gfx.circle_outline(self.x, self.y, radius, color, border_width=5)]

    def equip(self, player):
        super().equip(player)
        Weapon.damage = 100

    def charge(self):
        self.charging = True
        self.charge_amount += 1 * self.player.shoot_multiplier

    def release_charged_shot(self):
        amnt = self.charge_amount
        self.charging = False
        self.charge_amount = 0
        # Need to charge for at least 3 seconds.
        if amnt < 180:
            return None

        speed_x = 10
        if self.sprite.flipped:
            speed_x = -speed_x
        return self.fireball(speed_x, size=3)

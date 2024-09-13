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

import game.engine.hitbox as hitbox
from game.components.weapon.weapon import Weapon


class Poison(Weapon):
    def __init__(self, coords, name):
        rect = hitbox.Rectangle(coords.x - 16, coords.x + 16, coords.y - 16, coords.y + 16)
        super().__init__(
            coords=coords,
            name=name,
            display_name="Poison",
            tileset_path="resources/objects/weapons/poison.png",
            rect=rect,
        )

    def equip(self, player):
        super().equip(player)
        Weapon.damage = 10

    def fire(self, tics, _):
        self.player.decrease_health(10)

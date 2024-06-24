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

import components.weapon_systems.base as weapon
import components.projectile as projectile
import engine.hitbox as hitbox


class Poison(weapon.Weapon):
    COOL_DOWN_DELAY = 20

    def __init__(self, coords, name, collectable, flipped, damage):
        super().__init__(
            coords=coords,
            name=name,
            display_name="Poison",
            flipped=flipped,
            weapon_type="projectile",
            damage_type="single",
            damage_algo="constant",
            tileset_path="resources/objects/weapons/poison.tmx",
            collectable=collectable
        )

        self.destroyable = False

    def fire(self, _tics, _direction, _origin):
        if self.cool_down_timer == 0:
            self.cool_down_timer = self.COOL_DOWN_DELAY
            # *Glug glug* Mmm, refreshing!
            self.game.player.health -= 1
            self.game.player.sprite.set_flashing(True)

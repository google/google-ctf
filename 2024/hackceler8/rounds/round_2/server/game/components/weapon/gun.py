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

from game.components.weapon.weapon import Weapon


class Gun(Weapon):
    # min time in ticks between shots. Multiply by FPS to get seconds
    COOL_DOWN_DELAY = 20

    def __init__(self,
                 coords,
                 name,
                 display_name="Gun",
                 tileset_path="resources/objects/weapons/gun.png"):
        super().__init__(
            coords=coords,
            name=name,
            display_name=display_name,
            tileset_path=tileset_path,
        )

    def equip(self, player):
        super().equip(player)
        Weapon.damage = 10

    def fire(self, tics, direction):
        if self.cool_down_timer <= 0:
            self.cool_down_timer = self.COOL_DOWN_DELAY
            speed_x = 10
            if direction == "W":
                speed_x = -speed_x
            return self.fireball(speed_x)

class RedGun(Gun):
    def __init__(self, coords, name):
        super().__init__(
            coords=coords,
            name=name,
            display_name="Red Gun",
            tileset_path="resources/objects/weapons/red_gun.png",
        )

class BlueGun(Gun):
    def __init__(self, coords, name):
        super().__init__(
            coords=coords,
            name=name,
            display_name="Blue Gun",
            tileset_path="resources/objects/weapons/blue_gun.png",
        )

class BrownGun(Gun):
    def __init__(self, coords, name):
        super().__init__(
            coords=coords,
            name=name,
            display_name="Brown Gun",
            tileset_path="resources/objects/weapons/brown_gun.png",
        )

class GreenGun(Gun):
    def __init__(self, coords, name):
        super().__init__(
            coords=coords,
            name=name,
            display_name="Green Gun",
            tileset_path="resources/objects/weapons/green_gun.png",
        )

class OrangeGun(Gun):
    def __init__(self, coords, name):
        super().__init__(
            coords=coords,
            name=name,
            display_name="Orange Gun",
            tileset_path="resources/objects/weapons/orange_gun.png",
        )

class DGun(Gun):
    def __init__(self, coords, name):
        super().__init__(
            coords=coords,
            name=name,
            display_name="Gun",
            tileset_path="resources/character/Domino.h8t",
        )

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

import game.engine.generics as generics
import game.components.player
from game.components.projectile import Projectile
from game.engine.keys import Keys
from game.engine.point import Point


class Weapon(generics.GenericObject):
    damage = 10

    def __init__(
            self,
            coords,
            name,
            display_name,
            tileset_path=None,
            rect=None,
    ):
        super().__init__(
            coords,
            nametype="Weapon",
            tileset_path=tileset_path,
            rect=rect,
            can_flip=True,
        )
        self.name = name
        self.display_name = display_name
        self.cool_down_timer = 0
        self.charging = False

        # The player can only use (equip) one weapon at a time
        self.equipped = False
        self.player: 'game.components.player.Player' = None

    def tick(
            self, pressed_keys, newly_pressed_keys, tics
    ):
        super().tick()
        if self.cool_down_timer > 0:
            self.cool_down_timer -= 1 * self.player.shoot_multiplier
        if not self.equipped:
            return None
        self.move_to_player()
        if not self.player.dead and not self.player.immobilized:
            if Keys.SPACE in newly_pressed_keys:
                return self.fire(tics, self.player.face_towards)
            if Keys.SPACE in pressed_keys:
                self.charge()
                return None
            if self.charging and Keys.SPACE not in pressed_keys:
                return self.release_charged_shot()

    def move_to_player(self):
        self.place_at(self.player.x, self.player.y)
        if self.player.direction == self.player.DIR_W:
            self.sprite.set_flipped(True)
        elif self.player.direction == self.player.DIR_E:
            self.sprite.set_flipped(False)

    def fireball(self, speed_x, size=1):
        if self.player is not None and self.player.game.has_item("slow_bullet"):
            speed_x *= 0.5
        return Projectile(
            coords=Point(self.x, self.y + size * 4),
            speed_x=speed_x,
            speed_y=0,
            origin="player",
            base_damage=Weapon.damage,
            scale=size,
            weapon=self.display_name,
        )

    def equip(self, player):
        self.player = player
        self.equipped = True

    def fire(self, _tics, _target):
        pass  # Overridden by sub-classes.

    def charge(self):
        pass  # Overridden by chargeable sub-classes.

    def release_charged_shot(self):
        return None  # Overridden by chargeable sub-classes.

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
import logging

import components.weapon_systems.base as weapon
import components.projectile as projectile
import engine.hitbox as hitbox


class Cannon(weapon.Weapon):
    # min time in ticks between shots. Multiply by FPS to get seconds
    COOL_DOWN_TIME = 120  # 2 seconds

    def __init__(self, coords, name, collectable, flipped, damage):
        # Weapons are points, we center the outline around it
        outline = [
            hitbox.Point(coords.x - 16, coords.y - 16),
            hitbox.Point(coords.x + 16, coords.y - 16),
            hitbox.Point(coords.x + 16, coords.y + 16),
            hitbox.Point(coords.x - 16, coords.y + 16)
        ]
        super().__init__(
            coords=coords,
            name=name,
            display_name="Cannon",
            flipped=flipped,
            weapon_type="projectile",
            damage_type="single",
            damage_algo="constant",
            tileset_path="resources/objects/weapons/cannon.tmx",
            collectable=collectable,
            outline=outline
        )

        self.damage = damage if damage is not None else 30
        self.last_tick = 0
        self.charging = None
        self.charge_amount = 0

        self.destroyable = not self.collectable
        self.active = not self.collectable

    def draw(self):
        super().draw()
        if not self.charging:
            return
        radius = max(10, (270 - self.charge_amount)*0.5)
        if self.charge_amount < 60:
            color = arcade.csscolor.WHITE
        elif self.charge_amount < 120:
            color = arcade.csscolor.YELLOW
        else:
            color = arcade.csscolor.ORANGE
        arcade.draw_circle_outline(self.x, self.y, radius, color, border_width=5)

    def fire(self, tics, _, origin):
        if not self.ai_controlled:
            return
        if self.cool_down_timer == 0:
            self.cool_down_timer = self.COOL_DOWN_TIME
            return self._spawn_fireball(size=2, origin=origin, damage=self.damage)

    def charge(self):
        self.charging = True
        self.charge_amount += 1

    def release_charged_shot(self, origin):
        self.charging = False
        # Need to charge for at least 1 second
        proj = None
        if self.charge_amount >= 60:
            # Grows to at most 4x normal size in 4 seconds.
            size = self.charge_amount / 60
            size = min(size, 4)
            proj = self._spawn_fireball(size, origin, damage=20*size)
        self.charge_amount = 0
        return proj

    def _spawn_fireball(self, size, origin, damage):
        speed_x = 10
        if self.sprite.flipped:
            speed_x = -speed_x
        return projectile.Projectile(coords=hitbox.Point(self.x, 2+self.y+size*8),
                                     speed_x=speed_x, speed_y=0, origin=origin,
                                     damage_algo=self.damage_algo, damage_type=self.damage_type,
                                     base_damage=damage, scale=size)

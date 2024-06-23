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
import math
import pytiled_parser
import numpy as np
from copy import deepcopy

import constants
from engine import hitbox
from components.soul import Soul

from constants import SOUL_HP
from constants import SOUL_SPEED
from constants import SWING_TICKS

class GrenadeSystem:
    ACTIVE_LIMIT = 10

    def __init__(self, game, targets=None):
        if targets is None:
            targets = []

        self.targets = targets.copy()
        logging.debug(
            f"initialized grenade system with {len(self.targets)} targets.")

        # Variable stuff
        self.grenades = []
        self.tics = 0

        self.game = game

    def draw(self):
        for o in self.grenades:
            o.draw()


    def tick(self, newly_pressed_keys):
        self.tics += 1
        self._maybe_throw_soul(newly_pressed_keys)
        self._update_grenades()

    def _check_empty(self, player, obj):
        x0 = min(player.get_leftmost_point(), obj.get_leftmost_point())
        x1 = max(player.get_rightmost_point(), obj.get_rightmost_point())
        y0 = min(player.get_lowest_point(), obj.get_lowest_point())
        y1 = max(player.get_highest_point(), obj.get_highest_point())
        space = hitbox.Hitbox([
            hitbox.Point(x0+1, y1-1), hitbox.Point(x1-1, y1-1),
            hitbox.Point(x1-1, y0+1), hitbox.Point(x0+1, y0+1),
        ])
        cx, cy, nb = self.game.physics_engine._get_collisions_list(space)
        return not len(cx) and not len(cy)

    def _maybe_throw_soul(self, newly_pressed_keys):
        if len(self.grenades) >= self.ACTIVE_LIMIT:
            return
        if self.game.player.dead:
            return
        if arcade.key.T not in newly_pressed_keys:
            return

        # Swing from 0 deg to 90 deg in 2 secs
        angle = abs((self.tics % SWING_TICKS) / SWING_TICKS * 2 - 1) * 90
        rad = angle / 180 * math.pi
        x_speed, y_speed = math.cos(rad) * SOUL_SPEED, math.sin(rad) * SOUL_SPEED

        player_w = self.game.player.get_width()
        player_h = self.game.player.get_height()

        offset = (player_w ** 2 + player_h ** 2) ** 0.5 // 2 + 20
        offset_x, offset_y = math.cos(rad) * offset, math.sin(rad) * offset
        if self.game.player.face_towards == "W":
            offset_x = -offset_x
            x_speed = -x_speed

        offset_x += self.game.player.x
        offset_y += self.game.player.y
        x_speed += self.game.player.x_speed
        y_speed += self.game.player.y_speed

        coords = hitbox.Point(offset_x, offset_y)
        obj = Soul(coords, x_speed, y_speed, SOUL_HP)

        if not self._check_empty(self.game.player, obj):
            return

        self.game.player.decrease_health(SOUL_HP)
        self._add_grenade(obj)

    def _add_grenade(self, o):
        self.grenades.append(o)
        self.game.physics_engine.add_moving_object(o)

    def _remove_grenade(self, o):
        self.grenades.remove(o)
        self.game.physics_engine.remove_generic_object(o)

    def _update_grenades(self):
        for p in self.grenades.copy():
            if p.check_oob():
                self._remove_grenade(p)
                continue
            self._check_projectile(p)

    def _check_projectile(self, p):
        for t in self.targets.copy():
            c, _ = p.collides(t)
            if c:
                self._apply_damage(p, t)
                t.sprite.set_flashing(True)
                t.check_death()
                logging.info(f"New target health: {t.health}")
                logging.info(f"New target health: {t.dead}")
                if t.dead:
                    logging.debug("Target destroyed sir")
                    self.targets.remove(t)
                self._remove_grenade(p)
                return
        c, _ = self.game.player.collides(p)
        if c:
            self._apply_damage(p, self.game.player)
            self._remove_grenade(p)

    @staticmethod
    def _apply_damage(p, victim):
        if p.nametype == 'Soul':
            if victim.nametype != 'Player':
                victim.decrease_health(p.base_damage)
            else:
                victim.increase_health(p.base_damage)

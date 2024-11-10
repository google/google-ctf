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
import math
from typing import Optional

from game import constants
from game.components.projectile import Projectile
from game.engine import generics
from game.engine import hitbox
from game.engine.point import Point
from game.engine import modifier
from game.engine.walk_data import WalkData
import game.venator


class Enemy(generics.GenericObject):
    respawn_list = []

    def __init__(
            self,
            coords,
            tileset_path,
            name,
            damage=None,
            respawn=False,
            respawn_ticks=None,
            walk_data="",
            max_health=None,
            blocking=None,
            **kwargs,
    ):
        super().__init__(
            coords,
            nametype="Enemy",
            tileset_path=tileset_path,
            name=name,
            can_flip=True,
        )
        self.damage = damage
        self.does_respawn = respawn
        self.respawn_ticks = 300 if respawn_ticks is None else respawn_ticks
        self.respawn_timer = self.respawn_ticks
        self.shoot_timer = 0
        self.can_shoot = False
        self.shooting = False
        self.bullet = [0, 0, "resources/objects/bullet.png"]
        self.can_melee = False
        self.melee = False
        self.melee_range = 70
        self.walk_data = WalkData(self, walk_data)
        self.max_health = 50 if max_health is None else max_health
        self.should_block = False if blocking is None else blocking
        self.blocking = self.should_block
        self.dead = False
        self.death_timer = 0
        self.reset()
        # Will be overwritten
        self.game: Optional[game.venator.Venator] = None

        if kwargs:
            logging.warning(f"Unused arguments provided: {kwargs} for {name}")

    def reset(self):
        self.sprite.set_animation("idle")
        self._init_health()
        self.reset_position()
        self.walk_data.reset()

    def _init_health(self):
        self.set_health(self.max_health)
        self.dead = False
        self.death_timer = 60
        self.respawn_timer = self.respawn_ticks

    def get_draw_info(self):
        if self.dead and self.death_timer <= 0:
            return []
        return super().get_draw_info()

    def tick(self):
        super().tick()

        if self.game.has_item("healthy"):
            base = 30 if self.name == "block_enemy" else 50
            if self.health == base and self.max_health == base:
                self.max_health *= 2
                self.set_health(self.max_health)

        if self.sprite.alpha < 255:
            self.sprite.alpha = min(255, self.sprite.alpha + 10)

        if self.dead:
            self.sprite.set_animation("die")
            self.modifier = None
            self.blocking = False
            if self.death_timer > 0:
                self.death_timer -= 1
            elif self.does_respawn and self.death_timer == 0:
                self.death_timer = -1
                self.reset_position()
                self.walk_data.reset()
                Enemy.respawn_list.append(self)
            return

        if self.should_block:
            # Make should_block once the player moved out of the way.
            if not self.blocking and not self.collides(self.game.player):
                self.blocking = True

        if self._patrols_horizontally():
            walk_dir = self.walk_data.walk(self.game)
            if walk_dir == "E":
                self.sprite.set_flipped(False)
            if walk_dir == "W":
                self.sprite.set_flipped(True)
            if not self.shooting and not self.melee:
                if self.sprite.has_animation("walk") and self.prev_x != self.x:
                    self.sprite.set_animation("walk")
                else:
                    self.sprite.set_animation("idle")
        else:
            self.walk_data.walk(self.game)
            self.sprite.set_flipped(self.game.player.x < self.x)
            if not self.shooting and not self.melee:
                self.sprite.set_animation("idle")

        if self.can_shoot:
            self.shoot_timer += 1
            if self.shoot_timer >= 40:
                self.shooting = False
            if self.shoot_timer >= 60:
                self.shoot_timer = 0
                if self._sees_player():
                    self._shoot()
        if self.can_melee:
            # Attack the player if they come near.
            if self.collides(self.game.player) or (self._sees_player()
                and abs(self.game.player.x - self.x) < self.melee_range
                and abs(self.game.player.y - self.y) < self.melee_range):
                self._start_melee()
            else:
                self._stop_melee()

    def _patrols_horizontally(self):
        for w in self.walk_data.data:
            if isinstance(w, tuple) and (w[0] == "E" or w[0] == "W"):
                return True
        return False

    def _sees_player(self):
        if (self.x - self.game.player.x > 0) != self.sprite.flipped:
            return False
        x = abs(self.x - self.game.player.x)
        y = abs(self.y - self.game.player.y)
        return x * x + y * y < 400 * 400

    def _shoot(self):
        if not self.shooting and self.sprite.has_animation("shoot"):
            self.sprite.set_animation("shoot")
        self.shooting = True
        if self.sprite.flipped:
            x = self.x - self.bullet[0]
        else:
            x = self.x + self.bullet[0]
        y = self.y + self.bullet[1]
        img = self.bullet[2]
        angle = math.atan2(self.game.player.x - x, self.game.player.y - y)
        speed_x = 10 * math.sin(angle)
        speed_y = 10 * math.cos(angle)
        proj = Projectile(
            coords=Point(x, y),
            speed_x=speed_x,
            speed_y=speed_y,
            origin="AI",
            base_damage=10 if self.damage is None else self.damage,
            img = img,
        )
        self.game.projectile_system.active_projectiles.append(proj)

    def _start_melee(self):
        if not self.melee and self.sprite.has_animation("melee"):
            self.sprite.set_animation("melee")
        self.melee = True
        self.modifier = modifier.HealthDamage(
            min_distance=80, damage=1 if self.damage is None else self.damage)

    def _stop_melee(self):
        self.melee = False
        self.modifier = None

    @classmethod
    def respawn(cls):
        for e in cls.respawn_list.copy():
            if e.respawn_timer > 0:
                e.respawn_timer -= 1
            else:
                e.reset()
                e.sprite.alpha = 0
                cls.respawn_list.remove(e)


class Crab(Enemy):

    def __init__(
            self,
            coords,
            **kwargs,
    ):
        super().__init__(
            coords,
            tileset_path="resources/enemies/crab.h8t",
            **kwargs,
        )
        self._init_health()
        self.can_shoot = True
        self.bullet = [20, 0, "resources/objects/bullet.png"]
        rect = hitbox.Rectangle(coords.x - 22, coords.x + 22, coords.y - 16, coords.y + 16)
        self.update_hitbox(rect)


class Urchin(Enemy):

    def __init__(
            self,
            coords,
            **kwargs,
    ):
        super().__init__(
            coords,
            tileset_path="resources/enemies/urchin.h8t",
            **kwargs,
        )
        self._init_health()
        self.can_melee = True
        self.melee_range = 0
        rect = hitbox.Rectangle(coords.x - 23, coords.x + 23, coords.y - 15, coords.y + 15)
        self.update_hitbox(rect)


class Golem(Enemy):

    def __init__(
            self,
            coords,
            **kwargs,
    ):
        super().__init__(
            coords,
            tileset_path="resources/enemies/golem.h8t",
            **kwargs,
        )
        self._init_health()
        self.can_shoot = True
        self.bullet = [2, 15, "resources/enemies/golem_stone.png"]
        rect = hitbox.Rectangle(coords.x - 22, coords.x + 22, coords.y - 25, coords.y + 25)
        self.update_hitbox(rect)


class Orc(Enemy):

    def __init__(
            self,
            coords,
            **kwargs,
    ):
        super().__init__(
            coords,
            tileset_path="resources/enemies/orc.h8t",
            **kwargs,
        )
        self._init_health()
        self.can_melee = True
        self.melee_range = 70
        rect = hitbox.Rectangle(coords.x - 20, coords.x + 20, coords.y - 29, coords.y + 29)
        self.update_hitbox(rect)


class Vulture(Enemy):

    def __init__(
            self,
            coords,
            **kwargs,
    ):
        super().__init__(
            coords,
            tileset_path="resources/enemies/vulture.h8t",
            **kwargs,
        )
        self._init_health()
        self.can_shoot = True
        self.bullet = [2, -25, "resources/enemies/vulture_stone.png"]
        rect = hitbox.Rectangle(coords.x - 25, coords.x + 25, coords.y - 16, coords.y + 16)
        self.update_hitbox(rect)


class Eagle(Enemy):

    def __init__(
            self,
            coords,
            **kwargs,
    ):
        super().__init__(
            coords,
            tileset_path="resources/enemies/eagle.h8t",
            **kwargs,
        )
        self._init_health()
        self.can_melee = True
        self.melee_range = 0
        rect = hitbox.Rectangle(coords.x - 28, coords.x + 28, coords.y - 15, coords.y + 10)
        self.update_hitbox(rect)
        self.walk_data.walk_speed *= 2
        if self.damage is None:
            self.damage = 2


class Octopus(Enemy):

    def __init__(
            self,
            coords,
            **kwargs,
    ):
        super().__init__(
            coords,
            tileset_path="resources/enemies/octopus.h8t",
            **kwargs,
        )
        self._init_health()
        self.can_shoot = True
        self.bullet = [15, 0, "resources/objects/bullet.png"]
        rect = hitbox.Rectangle(coords.x - 24, coords.x + 24, coords.y - 25, coords.y + 25)
        self.update_hitbox(rect)


class Siren(Enemy):

    def __init__(
            self,
            coords,
            **kwargs,
    ):
        super().__init__(
            coords,
            tileset_path="resources/enemies/siren.h8t",
            **kwargs,
        )
        self._init_health()
        self.can_melee = True
        self.melee_range = 70
        rect = hitbox.Rectangle(coords.x - 13, coords.x + 13, coords.y - 30, coords.y + 30)
        self.update_hitbox(rect)


class Block(Enemy):

    def __init__(
            self,
            coords,
            color="grey",
            **kwargs,
    ):
        self.color = color
        super().__init__(
            coords,
            tileset_path="resources/enemies/" + self.color + "_block.h8t",
            **kwargs,
        )

        # Override max_health if not set
        if kwargs.get('max_health') is None:
            self.max_health = 30
        self._init_health()
        rect = hitbox.Rectangle(coords.x - 32, coords.x + 32, coords.y - 32, coords.y + 32)
        self.update_hitbox(rect)
        if kwargs.get('blocking') is None:
            self.should_block = True
        self.blocking = self.should_block


    def decrease_health(self, points, source=None):
        if self.color != "grey":
            if source and source.lower().startswith(self.color):
                return super().decrease_health(points, source)
            return False
        else:
            return super().decrease_health(points, source)

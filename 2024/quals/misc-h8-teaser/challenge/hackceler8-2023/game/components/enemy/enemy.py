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
import constants
import logging
import math
import pytiled_parser

from engine import generics
from engine import hitbox
from engine import modifier
from engine.walk_data import WalkData
from collections import deque
from components.projectile import Projectile

class Enemy(generics.GenericObject):
    respawn_list = []
    reverse_symbol = arcade.load_texture("resources/enemies/reverse.png")

    def __init__(self, coords, tileset_path, name,
                 damage, respawn, respawn_ticks, walk_data, control_inverter):
        super().__init__(coords, nametype="Enemy", tileset_path=tileset_path,
                         name=name, can_flip=True, can_flash=True)
        self.damage = 1 if damage is None else damage
        self.respawn = respawn
        self.respawn_ticks = 300 if respawn_ticks is None else respawn_ticks
        self.shoot_timer = 0
        self.can_shoot = False
        self.shooting = False
        self.walk_data = WalkData(self, walk_data)
        self.control_inverter = control_inverter
        self.max_health = 50
        self.reset()
        # Will be overwritten
        self.game = None

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

    def _spawnkill(self) -> bool:
        for o in self.game.objects:
            if o.nametype != "Spike" or not o.on:
                continue
            if o.get_rect().collides(self.get_rect()):
                return True
        return False

    def draw(self):
        if self.dead and self.death_timer <= 0:
            return
        super().draw()
        if self.game is None:
            return
        if self.control_inverter and self._sees_player():
            self.reverse_symbol.draw_scaled(self.x, self.y)

    def tick(self):
        super().tick()
        if self.sprite.alpha < 255:
            self.sprite.alpha = min(255, self.sprite.alpha + 10)

        if self.dead:
            self.set_animation("die")
            if self.death_timer > 0:
                self.death_timer -= 1
            elif self.respawn and self.death_timer == 0:
                self.death_timer = -1
                self.reset_position()
                self.walk_data.reset()
                Enemy.respawn_list.append(self)
            return

        if not self._visible_to_player():
            return

        if len(self.walk_data.data) > 0:
            walk_dir = self.walk_data.walk(self.game)
            if walk_dir == "E":
                self.sprite.set_flipped(False)
            if walk_dir == "W":
                self.sprite.set_flipped(True)
            if self.prev_x != self.x:
                self.set_animation("walk")
            else:
                self.set_animation("idle")
        else:
            self.sprite.set_flipped(self.game.player.x < self.x)
            self.set_animation("idle")

        if self.can_shoot:
            self.shoot_timer += 1
            if self.shoot_timer >= 30:
                self.shooting = False
            if self.shoot_timer >= 60:
                self.shoot_timer = 0
                if self._sees_player():
                    self._shoot()

    def set_animation(self, name):
        self.sprite.set_animation(name)

    def _sees_player(self):
        if (self.x - self.game.player.x > 0) != self.sprite.flipped:
            return False
        x = abs(self.x-self.game.player.x)
        y = abs(self.y-self.game.player.y)
        return x*x+y*y < 400*400

    def _visible_to_player(self):
        if abs(self.game.player.x - self.x) > constants.SCREEN_WIDTH + 100:
            return False
        if abs(self.game.player.y - self.y) > constants.SCREEN_HEIGHT + 100:
            return False
        return True

    def _shoot(self):
        self.shooting = True
        angle = math.atan2(self.game.player.x-self.x, self.game.player.y-self.y)
        speed_x = 10*math.sin(angle)
        speed_y = 10*math.cos(angle)
        proj = Projectile(
            coords=hitbox.Point(self.x, self.y), speed_x=speed_x, speed_y=speed_y,
            origin="AI", damage_algo="constant", damage_type="single")
        self.game.combat_system.active_projectiles.append(proj)
        self.game.physics_engine.moving_objects.append(proj)

    def respawn():
        for e in Enemy.respawn_list.copy():
            if e.respawn_timer > 0:
                e.respawn_timer -= 1
            elif not e._spawnkill():
                e.reset()
                e.sprite.alpha = 0
                Enemy.respawn_list.remove(e)

    def check_control_inversion(game):
        if(game.player == None):
            return
        inverted = False
        for o in game.objects:
            if o.nametype == "Enemy" and not o.dead and o.control_inverter and o._sees_player():
                inverted = True
        if(game.player.inverted_controls != inverted):
            game.player.inverted_controls = inverted

class StaticJellyfish(Enemy):
    def __init__(self, coords, name, damage, respawn, respawn_ticks, walk_data, control_inverter):
        self.shocking = False
        super().__init__(coords, tileset_path="resources/enemies/static_jellyfish.tmx",
                         name=name, damage=damage, respawn=respawn,
                         respawn_ticks=respawn_ticks, walk_data=walk_data, control_inverter=control_inverter)
        self.sprite.scale = 0.5
        self.max_health = 200
        self._init_health()
        outline = [
            hitbox.Point(coords.x - 18, coords.y - 40),
            hitbox.Point(coords.x + 18, coords.y - 40),
            hitbox.Point(coords.x + 18, coords.y + 40),
            hitbox.Point(coords.x - 18, coords.y + 40),
        ]
        self._update(outline)

    def tick(self):
        super().tick()
        # Make blocking once the player moved out of the way.
        if not self.blocking and not self.get_rect().collides(self.game.player.get_rect()):
            self.blocking = True
        if self.dead:
            self.modifier = None
            return

        # Shock the player if they come near.
        self.shocking = abs(self.game.player.x - self.x) < 70 and abs(self.game.player.y - self.y) < 70
        if self.shocking:
            self.modifier = modifier.HealthDamage(min_distance=80, damage=self.damage)
        else:
            self.modifier = None

    def set_animation(self, name):
        if name == "die":
            super().set_animation(name)
            return
        if self.shocking:
            self.sprite.set_animation("shock")
        else:
            self.sprite.set_animation("idle")

class MovingJellyfish(Enemy):
    def __init__(self, coords, name, damage, respawn, respawn_ticks, walk_data, control_inverter):
        super().__init__(coords, tileset_path="resources/enemies/moving_jellyfish.tmx",
                         name=name, damage=damage, respawn=respawn,
                         respawn_ticks=respawn_ticks, walk_data=walk_data, control_inverter=control_inverter)
        self.max_health = 50
        self._init_health()
        self.can_shoot = True
        outline = [
            hitbox.Point(coords.x - 20, coords.y - 20),
            hitbox.Point(coords.x + 20, coords.y - 20),
            hitbox.Point(coords.x + 20, coords.y + 22),
            hitbox.Point(coords.x - 20, coords.y + 22),
        ]
        self._update(outline)

    def set_animation(self, name):
        # No walk anim
        if name == "walk":
            name = "idle"
        super().set_animation(name)

class EvilCamera(Enemy):
    def __init__(self, coords, name, damage, respawn, respawn_ticks, walk_data, control_inverter):
        super().__init__(coords, tileset_path="resources/enemies/camera.tmx",
                         name=name, damage=damage, respawn=respawn,
                         respawn_ticks=respawn_ticks, walk_data=walk_data, control_inverter=control_inverter)
        self.max_health = 50
        self._init_health()
        self.can_shoot = True
        outline = [
            hitbox.Point(coords.x - 18, coords.y - 20),
            hitbox.Point(coords.x + 18, coords.y - 20),
            hitbox.Point(coords.x + 18, coords.y + 20),
            hitbox.Point(coords.x - 18, coords.y + 20),
        ]
        self._update(outline)

class Martian(Enemy):
    def __init__(self, coords, name, damage, respawn, respawn_ticks, walk_data, control_inverter):
        super().__init__(coords, tileset_path="resources/enemies/martian.tmx",
                         name=name, damage=damage, respawn=respawn,
                         respawn_ticks=respawn_ticks, walk_data=walk_data, control_inverter=control_inverter)
        self.max_health = 50
        self._init_health()
        self.can_shoot = True
        outline = [
            hitbox.Point(coords.x - 15, coords.y - 30),
            hitbox.Point(coords.x + 15, coords.y - 30),
            hitbox.Point(coords.x + 15, coords.y + 22),
            hitbox.Point(coords.x - 15, coords.y + 22),
        ]
        self._update(outline)
        if len(walk_data) > 0:
            self.sprite.set_texture("resources/enemies/martian_float.png")

    def set_animation(self, name):
        # No walk anim
        if name == "walk":
            name = "idle"
        super().set_animation(name)

    def tick(self):
        super().tick()
        if self.shooting:
            self.set_animation("shoot")

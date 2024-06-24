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

import logging
import math
import uuid

import xxhash

import constants
from engine import hitbox
from engine import modifier
from engine import sprite
from engine.quadtree import Bounds


class GenericObject(hitbox.Hitbox):
    def __init__(self, coords: hitbox.Point, nametype: str, tileset_path: str,
                 outline: list[hitbox.Point] = None, name: str = None,
                 can_flip: bool = False, can_flash: bool = False,
                 repeat_texture=False):
        # if no outline is provided we create a minuscule hitbox
        if outline is None:
            outline = [
                hitbox.Point(coords.x, coords.y),
                hitbox.Point(coords.x + 1, coords.y),
                hitbox.Point(coords.x + 1, coords.y + 1),
                hitbox.Point(coords.x, coords.y + 1)
            ]

        self.unique_id = str(uuid.uuid4())

        super().__init__(outline=outline)
        self.name = name
        self.can_flip = can_flip
        self.can_flash = can_flash
        self.orig_x = self.prev_x = self.x = coords.x
        self.orig_y = self.prev_y = self.y = coords.y
        self.walk_data = None

        self.dead = False
        self.respawn = False

        self.bounds = None
        self.hash = None

        self.repeat_texture = repeat_texture
        self.render_above_player = False

        self.enable_moving_physics = False
        self.base_x_speed = 0
        self.base_y_speed = 0
        self.x_speed = 0
        self.y_speed = 0
        self.z_speed = 0

        self.x_sticky = False
        self.y_sticky = False

        self.nametype = nametype
        self.modifier = None
        self.blocking = False
        self.load_sprite(tileset_path)

        # Used to check when object was collected
        self.collected_time = 0

        # Platformer variables
        self.affected_by_gravity = True
        self.collided = False
        self.in_the_air = True
        self.on_the_ground = True
        logging.debug(f"Created object of type {nametype} at {self.x, self.y} with "
                      f"corrdinates {[(i.x, i.y) for i in self.outline]}")

        self.update_bounds()
        self.dump_as_hash()

        self.health = 0
        self.prev_health = 0

        self.set_health(100)

        if self.hash is None:
            logging.critical("Hash missing")

    def load_sprite(self, tileset_path):
        if tileset_path is not None:
            prev_scale = self.sprite.scale if hasattr(self, "sprite") else 1
            repeat_size = None
            if self.repeat_texture:
                repeat_size = (self.get_width(), self.get_height())
            self.sprite = sprite.Sprite(tileset_path, can_flip=self.can_flip,
                                        can_flash=self.can_flash,
                                        repeat_size=repeat_size)
            self.sprite.scale = prev_scale
        else:
            self.sprite = None

    def update_bounds(self):
        self.bounds = Bounds(self.x, self.y, self.get_width(),
                             self.get_height(),
                             self.unique_id)

    def set_health(self, num):
        self.prev_health = self.health = num

    def reset(self):
        self.reset_speed()
        self.reset_position()
        self.dead = False
        self.set_health(100)
        self.in_the_air = True
        self.on_the_ground = True

    def reset_speed(self):
        self.x_speed = 0
        self.y_speed = 0
        self.z_speed = 0

    def reset_position(self):
        self.place_at(self.orig_x, self.orig_y)
        self.prev_x = self.x
        self.prev_y = self.y
        if self.walk_data:
            self.walk_data.reset()

    def check_death(self):
        if self.health == 0:
            self.dead = True

    def tick(self):
        self.prev_x = self.x
        self.prev_y = self.y
        self.check_death()
        if self.sprite is not None:
            self.sprite.tick()

    def draw(self):
        if self.sprite is not None:
            self.sprite.draw(self.x, self.y)

    def proximity(self, other):
        return math.sqrt((self.x - other.x) ** 2 + (self.y - other.y) ** 2)

    def update_hitbox(self, new_outline):
        self.update(new_outline)
        self.update_bounds()
        self.dump_as_hash()

    def update_position(self):
        if self.x_speed != 0 or self.y_speed != 0:
            self.prev_x = self.x
            self.prev_y = self.y
            self.move(round(constants.TICK_S * self.x_speed,5),
                      round(constants.TICK_S *
                            self.y_speed,5))
            logging.debug(f"New position is {self.x, self.y}")

    def move(self, x, y):
        self.x += x
        self.y += y
        self.update_hitbox([hitbox.Point(h.x + x, h.y + y) for h in self.outline])

    def set_speed(self, x_speed, y_speed):
        if x_speed is not None:
            self.x_speed = x_speed
        if y_speed is not None:
            self.y_speed = y_speed

    def place_at(self, x, y):
        self.move(x - self.x, y - self.y)

    def dump_as_hash(self):
        h = self.hck_hash + xxhash.xxh64(str((self.base_x_speed,
                                              self.y_speed,
                                              self.x_speed,
                                              self.y_speed,
                                              self.z_speed))).hexdigest()
        self.hash = xxhash.xxh64(h.encode()).hexdigest()
        if self.hash is None:
            logging.critical("Failed to get hash")

    def apply_modifier(self, mod: modifier.Modifier, distance):
        if self.dead:
            return
        match mod.__class__.__name__:
            case "HealthDamage":
                self.decrease_health(mod.calculate_effect(
                    mod.damage, distance))

            case "HealthIncreaser":
                self.increase_health(mod.calculate_effect(
                    mod.benefit, distance))

    def decrease_health(self, points):
        logging.debug(f"decreasing {self} health")
        points = int(max(1, round(points)))
        self.health = max(0, min(100, self.health - points))

    def increase_health(self, points):
        if self.dead:
            return
        logging.debug(f"regen {self} health")
        self.health = max(0, min(100, self.health + points))

    def dump(self):
        if self._dump is not None:
            return self._dump()

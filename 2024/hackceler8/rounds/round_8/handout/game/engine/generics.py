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
import dataclasses
import itertools
import logging
import math
from typing import Optional, Iterable

from game import constants
from game.engine import hitbox, gfx
from game.engine import modifier
from game.engine import sprite
from game.engine.point import Point
import xxhash


class GenericObject(hitbox.Hitbox):

    def __init__(
            self,
            coords: Point,
            nametype: str,
            tileset_path: Optional[str],
            rect: hitbox.Rectangle = None,
            name: str = None,
            blocking: bool = False,
            can_flip: bool = False,
    ):
        # if no rectangle is provided we create a minuscule hitbox
        if rect is None:
            rect = hitbox.Rectangle(coords.x, coords.x + 1, coords.y, coords.y + 1)

        super().__init__(rect.x1, rect.x2, rect.y1, rect.y2)
        self.name = name
        self.blocking = blocking
        self.can_flip = can_flip
        self.orig_x = self.prev_x = self.x = coords.x
        self.orig_y = self.prev_y = self.y = coords.y
        self.walk_data = None

        self.dead = False
        self.destructing = False
        self.respawn = False

        self.hash = None

        self.render_above_player = False

        self.enable_moving_physics = False
        self.base_x_speed = 0
        self.base_y_speed = 0
        self.x_speed = 0
        self.y_speed = 0

        self.nametype = nametype
        self.modifier = None
        self.sprite: Optional[sprite.Sprite] = None
        self.load_sprite(tileset_path)

        # Used to check when object was collected
        self.collected_time = 0

        self.in_the_air = True

        self.dump_as_hash()

        self.health = 0
        self.prev_health = 0

        self.set_health(100)

        if self.hash is None:
            logging.critical("Hash missing")

    def on_player_collision(self, player):
        pass

    def load_sprite(self, tileset_path):
        if tileset_path is not None:
            prev_scale = self.sprite.scale if self.sprite is not None else 1
            self.sprite = sprite.Sprite(
                tileset_path,
                can_flip=self.can_flip,
            )
            self.sprite.scale = prev_scale
        else:
            self.sprite = None

    def set_health(self, num):
        self.prev_health = self.health = num

    def reset(self):
        self.reset_speed()
        self.reset_position()
        self.dead = False
        self.set_health(100)
        self.in_the_air = True

    def reset_speed(self):
        self.x_speed = 0
        self.y_speed = 0

    def reset_position(self):
        self.place_at(self.orig_x, self.orig_y)
        self.prev_x = self.x
        self.prev_y = self.y
        if self.walk_data:
            self.walk_data.reset()

    def check_death(self):
        if self.health <= 0:
            self.dead = True

    def tick(self):
        self.prev_x = self.x
        self.prev_y = self.y
        self.check_death()
        if self.sprite is not None:
            self.sprite.tick()

    def draw(self):
        raise NotImplementedError

    def get_draw_info(self) -> gfx.IterableParams:
        ret = None
        if self.sprite is not None:
            ret = self.sprite.get_draw_info(self.x, self.y)
        else:
            ret = []
        return ret

    def proximity(self, other):
        return math.sqrt((self.x - other.x) ** 2 + (self.y - other.y) ** 2)

    def update_hitbox(self, new_rect):
        self.update(new_rect)
        self.dump_as_hash()

    def update_position(self):
        if self.x_speed != 0 or self.y_speed != 0:
            self.prev_x = self.x
            self.prev_y = self.y
            self.move(self.x_speed, self.y_speed)
            logging.debug(f"New position is {self.x, self.y}")

    def move(self, x, y):
        self.x += x
        self.y += y
        self.x = round(self.x, 2)
        self.y = round(self.y, 2)
        self.update_hitbox(self.offset(x, y))

    def set_speed(self, x_speed, y_speed):
        if x_speed is not None:
            self.x_speed = x_speed
        if y_speed is not None:
            self.y_speed = y_speed

    def place_at(self, x, y):
        self.move(x - self.x, y - self.y)

    def dump_as_hash(self):
        h = (
                self.rect_hash
                + xxhash.xxh64(
            str((
                self.base_x_speed,
                self.y_speed,
                self.x_speed,
                self.y_speed,
            ))
        ).hexdigest()
        )
        self.hash = xxhash.xxh64(h.encode()).hexdigest()
        if self.hash is None:
            logging.critical("Failed to get hash")

    def apply_modifier(self, mod: modifier.Modifier, distance):
        if self.dead:
            return
        match mod.__class__.__name__:
            case "HealthDamage":
                self.decrease_health(mod.calculate_effect(mod.damage, distance), "health_damage_mod")

            case "HealthIncreaser":
                self.increase_health(mod.calculate_effect(mod.benefit, distance))

    def decrease_health(self, points, source=None):
        logging.debug(f"decreasing {self} health")
        self.health = max(0, self.health - points)
        if self.health <= 0:
            self.dead = True
        return True

    def increase_health(self, points):
        if self.dead:
            return
        logging.debug(f"regen {self} health")
        self.health = max(0, min(100, self.health + points))

    def dump(self):
        if self._dump is not None:
            return self._dump()

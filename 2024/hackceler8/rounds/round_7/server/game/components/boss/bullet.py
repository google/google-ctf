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

import math
from game.engine import gfx
from dataclasses import replace
from typing import Iterable

class Bullet:
    def __init__(
            self,
            boss,
            x,
            y,
            speed,
            angle,
            damage=10,
            radius=20,
            color=(255, 233, 0, 0),
            soft=True,
    ):
        self.x = x
        self.y = y
        self.radius = radius
        self.damage = damage
        self.boss = boss
        self.hitbox_w = radius
        self.speed = speed
        self.angle = angle
        self.updater = self.run()
        self.intangible = True
        self.scale = 0
        self.color = color
        self.soft = soft

    def get_draw_info(self) -> Iterable[gfx.BaseDrawParams]:
        info = gfx.circle_filled(self.x, self.y, self.radius * self.scale, self.color, self.soft)
        info = replace(info, above_sprite=True)
        return [info]

    def move_simple(self):
        self.x += self.speed * math.cos(math.radians(self.angle))
        self.y += self.speed * math.sin(math.radians(self.angle))

    def spawn_anim(self):
        self.intangible = True
        for i in range(10):
            progress = (i / (10 - 1)) ** 2
            self.color = (self.color[0], self.color[1], self.color[2], int(255 * progress))
            self.scale = progress
            yield
        self.intangible = False

    def despawn_anim(self):
        self.intangible = True
        for i in range(10):
            progress = (i / (10 - 1)) ** 2
            self.color = (self.color[0], self.color[1], self.color[2], int(255 * (1 - progress)))
            self.scale = 1 + progress
            yield
        self.boss.destroy_bullet(self)
        yield

    def run(self):
        raise NotImplementedError

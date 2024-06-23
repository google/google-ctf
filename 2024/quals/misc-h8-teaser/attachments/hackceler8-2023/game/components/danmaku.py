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

import math
from collections import deque

import arcade
import constants


class Bullet(arcade.SpriteCircle):
    def __init__(self, system, x, y, speed, angle, radius=20, color=(255, 233, 0),
                 soft=True):
        super().__init__(radius, color=(255, 255, 255), soft=soft)
        self.system = system
        self.hitbox_radius = radius / 2
        self.speed = speed
        self.angle = angle
        self.set_position(x, y)
        self.updater = self.run()
        self.intangible = True
        self.alpha = 0
        self.scale = 0
        self.color = color

    def move_simple(self):
        x, y = self.position
        x += self.speed * constants.TICK_S * math.cos(math.radians(self.angle))
        y += self.speed * constants.TICK_S * math.sin(math.radians(self.angle))
        self.set_position(x, y)

    def spawn_anim(self):
        self.intangible = True
        for i in range(10):
            progress = (i / (10 - 1)) ** 2
            self.alpha = int(255 * progress)
            self.scale = progress
            yield
        self.intangible = False

    def despawn_anim(self):
        self.intangible = True
        for i in range(10):
            progress = (i / (10 - 1)) ** 2
            self.alpha = int(255 * (1 - progress))
            self.scale = 1 + progress
            yield
        self.system.destroy(self)
        yield


class SimpleBullet(Bullet):
    def __init__(self, system, x, y, speed, angle, radius=20, color=(255, 233, 0),
                 soft=True):
        super().__init__(system, x, y, speed, angle, radius=radius, color=color,
                         soft=soft)

    def run(self):
        yield from self.spawn_anim()
        while True:
            self.move_simple()
            yield


class PlayerBullet(SimpleBullet):
    def __init__(self, system, x, y, speed, angle, radius=15):
        super().__init__(system, x, y, speed, angle, radius=radius, color=(255, 233, 0),
                         soft=False)
        self.intangible = False
        self.alpha = 255
        self.scale = 1

    def despawn_anim(self):
        self.intangible = True
        for i in range(10):
            progress = (i / (10 - 1)) ** 2
            self.alpha = int(255 * (1 - progress))
            self.scale = 1 + progress
            yield
        self.system.player_destroy(self)
        yield

    def run(self):
        yield
        while True:
            self.move_simple()
            yield

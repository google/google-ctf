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

from engine import generics
from engine import hitbox
import logging


class MovingPlatform(generics.GenericObject):
    def __init__(self, coords, name, x_speed, y_speed, min_dx, max_dx, min_dy, max_dy):
        path = "resources/objects/moving_platforms/%s.tmx" % name[
                                                             len("moving_platform_"):]
        super().__init__(coords, nametype="MovingPlatform", tileset_path=path,
                         name=name)

        self.orig_x = self.x
        self.orig_y = self.y
        self.orig_x_speed = x_speed
        self.orig_y_speed = y_speed
        self.x_speed = x_speed
        self.y_speed = y_speed
        self.min_dx = min_dx
        self.max_dx = max_dx
        self.min_dy = min_dy
        self.max_dy = max_dy

        w, h = self.sprite.get_dimensions()
        outline = [
            hitbox.Point(coords.x - w / 2, coords.y - h / 2),
            hitbox.Point(coords.x + w / 2, coords.y - h / 2),
            hitbox.Point(coords.x + w / 2, coords.y + h / 2),
            hitbox.Point(coords.x - w / 2, coords.y + h / 2),
        ]
        self._update(outline)

    def reset(self):
        self.reset_position()
        self.x_speed = self.orig_x_speed
        self.y_speed = self.orig_y_speed

    def move_around(self):
        if self.x - self.orig_x >= self.max_dx:
            self.x_speed = -self.x_speed
        if self.x - self.orig_x <= self.min_dx:
            self.x_speed = -self.x_speed

        if self.y - self.orig_y >= self.max_dy:
            self.y_speed = -self.y_speed
        if self.y - self.orig_y <= self.min_dy:
            self.y_speed = -self.y_speed

        self.move(self.x_speed, self.y_speed)
        for o in self.game.objects:
            if o.nametype == "Flag" and abs(o.x-self.x)+abs(o.y-self.y) <= 40:
                o.move(self.x_speed, self.y_speed)

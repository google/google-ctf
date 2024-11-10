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
import itertools
import logging
from game.engine import generics
from game.engine import hitbox
from game.engine import gfx


class Portal(generics.GenericObject):

    def __init__(
            self,
            coords,
            size,
            name,
            dest,
            x_speed=None,
            y_speed=None,
            usage_limit=None,
            visible=True,
    ):
        rect = hitbox.Rectangle(coords.x, coords.x + size.width, coords.y - size.height, coords.y)
        super().__init__(coords, "Portal", None, rect)
        self.name = name
        self.dest = dest
        self.size = size
        self.x_speed = x_speed
        self.y_speed = y_speed
        self.usage_count = 0
        self.usage_limit = usage_limit
        self.visible = visible

    def reset(self):
        super().reset()
        self.usage_count = 0

    def on_player_collision(self, player):
        if player.dead:
            return
        if not self.deduct_usage():
            logging.info("Punished due to exceeding Portal usage limit.")
            player.dead = True

        player.place_at(self.dest.x, self.dest.y)
        player.set_speed(self.x_speed, self.y_speed)
        player.in_the_air = True

    def get_draw_info(self):
        ret = []
        if self.visible:
            r = self.size.width // 2
            return [gfx.circle_outline(
                self.x + r, self.y - r, r * 1.2, (0,0,255,255), border_width=5
            )]
        else:
            ret = []
        return itertools.chain(super().get_draw_info(), ret)

    def deduct_usage(self):
        if self.usage_limit is None:
            return True

        if self.usage_count >= self.usage_limit:
            return False

        self.usage_count += 1
        return True

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
from engine import generics
from engine import hitbox


class SpeedTile(generics.GenericObject):
    def __init__(self, coords, name):
        self.perimeter = [
            hitbox.Point(coords.x - 32, coords.y + 1),
            hitbox.Point(coords.x + 32, coords.y + 1),
            hitbox.Point(coords.x + 32, coords.y - 1),
            hitbox.Point(coords.x - 32, coords.y - 1),
        ]
        super().__init__(coords, "SpeedTile", "resources/objects/speed_tile.tmx", self.perimeter, name=name)
        self.sprite.set_animation("scroll")
        # Will be overwritten
        self.game = None

    def tick(self):
        super().tick()

        already_pushing = self.game.player.can_control_movement and self.game.player.push_speed > 0

        c, _ = self.collides(self.game.player)
        if c:
            self.game.player.can_control_movement = False
            self.game.player.direction = self.game.player.DIR_N
            if not already_pushing:
                self.game.player.push_speed += 2500
        else:
            self.game.player.can_control_movement = True

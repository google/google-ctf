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
from game.engine import generics
from game.engine import hitbox


class BossGate(generics.GenericObject):
    def __init__(self, coords, name, stars_needed):
        super().__init__(
            coords, nametype="BossGate",
            tileset_path="resources/portals/boss_gate.h8t",
            name=name,
        )
        self.on = False
        self.stars_needed = stars_needed
        self.blocking = False
        self.sprite.set_animation("off")
        _, h = self.sprite.get_dimensions()
        rect = hitbox.Rectangle(coords.x - 35, coords.x + 35, coords.y - h / 2, coords.y + h / 2 - 8)
        self.update_hitbox(rect)
        self.place_at(self.x, self.y + h / 2)
        self.orig_y = self.y

    def tick(self):
        super().tick()
        if not self.on:
            if self.game.match_flags.stars() >= self.stars_needed:
                self.on = True
                self.sprite.set_animation("on")

    def on_player_collision(self, player):
        if self.on:
            self.game.load_map(self.name.removesuffix("_gate"))

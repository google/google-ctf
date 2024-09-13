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

from game.engine import generics
from game.engine import hitbox


class Warp(generics.GenericObject):

    def __init__(self, coords, name):
        self.map_name = name.removesuffix("_warp")
        super().__init__(
            coords, nametype="warp",
            tileset_path="resources/portals/%s_portal.h8t" % self.map_name
        )
        w, h = self.sprite.get_dimensions()
        rect = hitbox.Rectangle(
            coords.x - 24, coords.x + 24,
            coords.y - h / 2, coords.y + h / 2 - 10,
        )
        self.update_hitbox(rect)
        self.place_at(self.x, self.y + h / 2)
        self.orig_y = self.y

        self.sprite.set_animation("portal")

    def on_player_collision(self, player):
        if player.dead:
            return
        self.game.load_map(self.map_name if self.game.current_map == "base" else "base")

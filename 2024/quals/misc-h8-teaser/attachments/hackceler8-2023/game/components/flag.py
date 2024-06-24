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
from engine import generics
from engine import hitbox


class Flag(generics.GenericObject):
    FLAGS = {
        # Redacted, go make the server send it to you
    }
    def __init__(self, coords, name):
        super().__init__(coords, "Flag", "resources/objects/flag.tmx", None, name)
        self.blocking = False
        self.sprite.set_animation("flag")
        w, h = self.sprite.get_dimensions()
        outline = [
            hitbox.Point(coords.x - w / 2, coords.y - h / 2),
            hitbox.Point(coords.x + w / 2, coords.y - h / 2),
            hitbox.Point(coords.x + w / 2, coords.y + h / 2),
            hitbox.Point(coords.x - w / 2, coords.y + h / 2),
        ]
        self._update(outline)

    def tick(self):
        super().tick()
        if self.game.player.get_rect().collides(self.get_rect()):
            if self.game.net is None:
                self.game.get_flag("Re-run the game on the server to get the flag!")
                return
            flag = self.FLAGS.get(self.name, "Waiting for server...")
            self.game.get_flag(flag)

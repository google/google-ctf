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


class Switch(generics.GenericObject):
    def check_all_pressed(game):
        found = False
        for o in game.objects:
            if o.nametype == "Switch":
                found = True
                if not o.pressed:
                    return
        if not found:  # No switches
            return
        # Deactivate spikes.
        for o in game.objects:
            if o.nametype == "Switch":
                o.stuck = True
            if o.nametype == "Spike":
                o.deactivate()

    def __init__(self, coords):
        super().__init__(coords, nametype="Switch",
                         tileset_path="resources/objects/switch.tmx",
                         name="Switch", can_flip=False, can_flash=False)
        self.sprite.set_animation("off")
        self.pressed = False
        self.stuck = False
        outline = [
            hitbox.Point(coords.x - 16, coords.y - 16),
            hitbox.Point(coords.x + 16, coords.y - 16),
            hitbox.Point(coords.x + 16, coords.y + 16),
            hitbox.Point(coords.x - 16, coords.y + 16),
        ]
        self._update(outline)
        # Will be overwritten
        self.game = None

    def tick(self):
        super().tick()
        self._update_pressed()
        self.sprite.set_animation("on" if self.pressed else "off")

    def _update_pressed(self):
        if self.stuck:
            self.pressed = True
            return

        self.pressed = False
        rect = self.get_rect()
        if rect.collides(self.game.player.get_rect()):
            self.pressed = True
            return
        for o in self.game.objects:
            if o.nametype == "Enemy" and not o.dead:
                if rect.collides(o.get_rect()):
                    self.pressed = True
                    return

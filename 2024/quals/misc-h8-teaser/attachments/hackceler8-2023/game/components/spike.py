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
import pytiled_parser
import random

from engine import generics
from engine import hitbox


class Spike(generics.GenericObject):

    def __init__(self, coords, rng: bool, rng_type='prng'):
        super().__init__(coords, nametype="Spike",
                         tileset_path="resources/objects/spikes.tmx",
                         name="Spike", can_flip=False, can_flash=False)
        self.rng = rng
        self.rng_type = rng_type
        self.on = not rng
        self._update_animation()
        self.update_hitbox([
            hitbox.Point(self.x - 32, self.y - 32),
            hitbox.Point(self.x + 32, self.y - 32),
            hitbox.Point(self.x + 32, self.y + 32),
            hitbox.Point(self.x - 32, self.y + 32),
        ])
        self.tic = 0
        # Will be overwritten
        self.game = None

    def deactivate(self):
        self.rng = False
        self.on = False

    def tick(self):
        super().tick()
        self._maybe_change_setting()
        self._update_animation()
        if not self.on:
            return
        for o in self.game.objects:
            if (o.nametype == "Enemy" and not o.dead
                    and self.get_rect().collides(o.get_rect())):
                o.decrease_health(o.health)
                o.check_death()
        if (not self.game.player.dead
                and self.get_rect().collides(self.game.player.get_rect())):
            self.game.player.sprite.set_flashing(True)
            self.game.player.decrease_health(self.game.player.health)
            self.game.player.check_death()

    def _maybe_change_setting(self):
        if not self.rng:  # Always stays the same.
            return
        self.tic += 1
        if self.tic >= 60:
            self.tic = 0
            rng = self.game.rng_system.get(self.rng_type)
            self.on = bool(rng.getrandbits(1))

    def _update_animation(self):
        self.sprite.set_animation("on" if self.on else "off")

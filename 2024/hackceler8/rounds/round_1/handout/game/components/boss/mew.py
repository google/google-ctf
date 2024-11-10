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


class Mew(generics.GenericObject):
    FALL_HEIGHT = 1000

    def __init__(self, coords, game):
        self.game = game
        coords.y += self.FALL_HEIGHT
        super().__init__(
            coords,
            nametype="Mew",
            tileset_path="resources/NPCs/Mew.h8t",
            name="Mew",
            can_flip=True,
        )
        self.timer = 0

    def tick(self):
        self.sprite.set_flipped(self.game.player.x < self.x)
        if self.timer < 110:
            self.timer += 1
            self.y -= self.FALL_HEIGHT / 120
            self.sprite.set_animation("jump")
        else:
            self.sprite.set_animation("idle")

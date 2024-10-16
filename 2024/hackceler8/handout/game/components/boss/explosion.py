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


class Explosion(generics.GenericObject):

    def __init__(self, coords, small):
        if small:
            tileset = "resources/villain/explosion_small.h8t"
        else:
            tileset = "resources/villain/explosion_big.h8t"
        super().__init__(coords, "Explosion", tileset)
        self.sprite.set_animation("boom")
        self.ticks = 0

    def tick(self):
        super().tick()
        self.ticks += 1

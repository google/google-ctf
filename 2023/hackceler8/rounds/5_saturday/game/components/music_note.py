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
import random

class MusicNote(generics.GenericObject):
    def __init__(self, coords):
        super().__init__(coords, "MusicNote", "resources/objects/music.tmx")
        self.sprite.set_animation(str(random.randint(0, 3)))
        self.dx = self.dy = 0
        while self.dx == 0 and self.dy == 0:
            self.dx = random.randint(-2, 2)
            self.dy = random.randint(-2, 2)
        self.timer = 0
    def tick(self):
        super().tick()
        self.move(self.dx, self.dy)
        self.timer += 1
        if self.timer > 60:
            self.sprite.alpha = max(0, self.sprite.alpha-10)

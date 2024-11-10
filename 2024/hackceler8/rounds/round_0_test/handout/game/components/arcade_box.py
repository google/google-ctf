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
from game.engine.keys import Keys


class ArcadeBox(generics.GenericObject):

    def __init__(self, coords):
        super().__init__(
            coords=coords,
            nametype="ArcadeBox",
            tileset_path="resources/objects/arcade_box.h8t",
            can_flip=True,
            blocking=True,
        )
        self.sprite.set_animation("off")
        self.sprite.set_flipped(True)
        w, h = self.sprite.get_dimensions()
        rect = hitbox.Rectangle(
            coords.x - w * 0.5, coords.x + w * 0.5,
            coords.y - h * 0.5, coords.y + h * 0.5,
        )
        self.update_hitbox(rect)
        self.timer = 0

    def tick(self):
        super().tick()
        if self.sprite.animation.name == "on":
            self.timer += 1
            if self.timer == 60:
                self.game.init_arcade_system()
                self.sprite.set_animation("turn-off")
            return

        if not Keys.E in self.game.newly_pressed_keys:
            return
        if self.game.player.dead:
            return
        if (self.expand(20).collides(self.game.player)):
            self.sprite.set_animation("on")
            self.timer = 0

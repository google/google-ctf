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

from game.engine import hitbox
from game.components.npc.npc import Npc


class TrappedNpc(Npc):

    def __init__(self, tileset_path, text, stars, **kwargs):
        super().__init__(
            scale=1,
            tileset_path=tileset_path,
            **kwargs,
        )
        self.text = text
        self.stars = stars

    def dialogue(self):
        def get_stars(text):
            self.game.free_npc(self, self.stars)

        star_str = "star" if self.stars == 1 else "stars"
        self.display_textbox(self.text + f"\n\nDomino received *{self.stars}* {star_str}!", process_fun=get_stars)


class Quackington(TrappedNpc):
    def __init__(self, **kwargs):
        item = None
        super().__init__(
            "resources/NPCs/Quackington.h8t",
            "Thanks for freeing me, quack!",
            **kwargs,
        )
        coords = kwargs['coords']
        rect = hitbox.Rectangle(coords.x - 36, coords.x + 36, coords.y - 31, coords.y + 37)
        self.update_hitbox(rect)


class Jessse(TrappedNpc):
    def __init__(self, **kwargs):
        item = None
        super().__init__(
            "resources/NPCs/Jessse.h8t",
            "Thanksssss for releassssing me!",
            **kwargs,
        )
        coords = kwargs['coords']
        rect = hitbox.Rectangle(coords.x - 15, coords.x + 15, coords.y - 25, coords.y + 25)
        self.update_hitbox(rect)


class Trasher(TrappedNpc):
    def __init__(self, **kwargs):
        item = None
        super().__init__(
            "resources/NPCs/Trasher.h8t",
            "Thanks for freeing me!",
            **kwargs,
        )
        coords = kwargs['coords']
        rect = hitbox.Rectangle(coords.x - 20, coords.x + 20, coords.y - 30, coords.y + 35)
        self.update_hitbox(rect)


class Casher(TrappedNpc):
    def __init__(self, **kwargs):
        item = None
        super().__init__(
            "resources/NPCs/Casher.h8t",
            "Thanks fer freein' me jimbo!",
            **kwargs,
        )
        coords = kwargs['coords']
        rect = hitbox.Rectangle(coords.x - 20, coords.x + 20, coords.y - 30, coords.y + 35)
        self.update_hitbox(rect)


class Raibbit(TrappedNpc):
    def __init__(self, **kwargs):
        item = None
        super().__init__(
            "resources/NPCs/Raibbit.png",
            "* BEEEP *\nGRATITUDE PROTOCOLS ACTIVATED\nTHANK YOU FOR YOUR ASSISTANCE IN FREEING ME",
            **kwargs,
        )
        coords = kwargs['coords']
        rect = hitbox.Rectangle(coords.x - 80, coords.x + 80, coords.y - 93, coords.y + 80)
        self.update_hitbox(rect)
        self.sprite.scale = 0.7
        self.render_above_player = True

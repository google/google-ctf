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

import random
from game.constants import SCREEN_WIDTH, SCREEN_HEIGHT
from game.engine import gfx

BG_ATLAS = gfx.TextureAtlas(spacing=0, size=6144)


class BossBG:
    def __init__(self):
        self.tics = 0
        self.bgs = {}
        self.num = 1
        self.glitch = False
        self.is_dialogue = False
        self.current = None
        for t in ["dialogue_", "fighting_"]:
            for i in [str(a) for a in range(1, 7)]:
                for g in ["g", ""]:
                    img = BG_ATLAS.load(gfx._resolve_path("resources/levels/boss/bg/%s.png" % (t+i+g)), 0, 0)
                    l = gfx.SpriteLayer()
                    l.add(gfx.SpriteDrawParams(x=SCREEN_WIDTH//2, y=SCREEN_HEIGHT//2, tex=img))
                    l.update_all_buffers()
                    self.bgs[t+i+g] = l
        self.current = self.bgs["dialogue_1"]

    def tick(self):
        changed = False
        if self.tics % 120 == 110 and random.choice([True, False]):
            changed = True
            self.glitch = True
        elif self.tics % 120 == 10:
            changed = True
            self.glitch = False
        if self.tics % 600 == 590:
            changed = True
            self.glitch = True
        if self.tics % 600 == 0:
            changed = True
            self.num = random.randrange(1, 7)

        if changed:
            self.current = self.bgs["%s%s%s" % (
                "dialogue_" if self.is_dialogue else "fighting_", str(self.num), "g" if self.glitch else "")]

        self.tics += 1

    def white_text(self):
        return self.num != 4 and self.num != 6 # Cloud + arcade level

    def draw(self):
        self.current.draw_all_cached()

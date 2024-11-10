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
from __future__ import annotations

import random
from typing import Optional, TYPE_CHECKING, Iterable

from game.components.boss.explosion import Explosion
from game.components.boss.mew import Mew
from game.engine import generics, gfx
from game.engine.keys import Keys
from game.engine.point import Point

if TYPE_CHECKING:
    from game.venator import Venator


class Boss(generics.GenericObject):

    def __init__(self, coords, name, tileset_path):
        super().__init__(
            coords,
            nametype="Boss",
            tileset_path=tileset_path,
            name=name,
            blocking=False,
            can_flip=True,
        )
        self.game: Optional[Venator] = None
        self.destructing = False
        self.dead = False
        self.mew: Optional[Mew] = None

        self.explosions = []

        self.destruct_timer = 0

        self.sprite.set_animation("idle")

    def destruct(self, _=None):
        self.sprite.set_animation("die")
        self.destructing = True
        self.destruct_timer = 300

    def _add_explosion(self, small=True):
        x = self.x
        y = self.y
        if small:
            x += random.randint(-100, 100)
            y += random.randint(-150, 150)
        self.explosions.append(Explosion(Point(x, y), small))

    def tick(self):
        super().tick()

        self._maybe_chat()

        if self.mew is not None:
            self.mew.tick()

        if self.destructing:
            if self.destruct_timer > 120:
                if self.destruct_timer % 10 == 0:
                    self._add_explosion()
            elif self.destruct_timer == 120:
                self._add_explosion(small=False)
                if self.game.match_flags.last_boss():
                    self._free_mew()
            self.destruct_timer -= 1
            if self.destruct_timer <= 0:
                self.dead = True
                self.game.match_flags.obtain_flag(self.name)
                self.game.save_file.save(self.game)
        for e in list(self.explosions):
            e.tick()
            if e.ticks > 120:
                self.explosions.remove(e)

    def get_draw_info(self) -> gfx.IterableParams:
        ret = []
        if not self.destructing or self.destruct_timer >= 120:
            ret.append(super().get_draw_info())
        if self.mew is not None:
            ret.append(self.mew.get_draw_info())
        for e in self.explosions:
            ret.append(e.get_draw_info())
        return ret

    def draw_gui(self):
        pass

    def reload_module(self):
        pass

    def _maybe_chat(self):
        if self.game.player.dead or self.destructing or self.dead:
            return
        if (self.expand(100).collides(self.game.player) and
                Keys.E in self.game.newly_pressed_keys and
                self.game.textbox is None):
            self._chat()

    def _chat(self):
        pass

    def _free_mew(self):
        self.mew = Mew(Point(self.orig_x, self.orig_y-151), self.game)

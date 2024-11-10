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
from game.engine import generics
from game.engine import hitbox
from game.components.items import Item
from game.engine.keys import Keys


class KeyGate(generics.GenericObject):
    gate_states = {}

    def __init__(self, coords, name):
        rect = hitbox.Rectangle(coords.x - 13, coords.x + 19, coords.y - 48, coords.y + 48)
        super().__init__(
            coords, nametype="KeyGate",
            tileset_path="resources/objects/key_gate.h8t",
            rect=rect, name=name,
        )
        self.on = True
        self.blocking = True
        self.sprite.set_animation("on")

    def tick(self):
        self._refresh_state()
        if (not self.game.player.dead and
            Keys.E in self.game.newly_pressed_keys and
            self._interact_rect().collides(self.game.player)):
            self._toggle()
        super().tick()

    def _refresh_state(self):
        if self.name in KeyGate.gate_states:
            self.on = KeyGate.gate_states[self.name]
        if (self.sprite.get_animation() == "on") != self.on:
            self.sprite.set_animation("on" if self.on else "off")
            self.game.save_file.save(self.game)
        self.blocking = self.on

    def _interact_rect(self):
        return hitbox.Rectangle(self.x1 - 20, self.x1, self.y1, self.y2)

    def _toggle(self):
        if self.on:
            if self._has_key():
                self._remove_key()
                self.on = False
        else:
            self._give_key()
            self.on = True
            if self.collides(self.game.player):
                self.game.player.move(self.get_leftmost_point() - self.game.player.get_rightmost_point(), 0)
                self.game.player.x_speed = 0
        KeyGate.gate_states[self.name] = self.on

    def _has_key(self) -> bool:
        return any([i.name == "key" for i in self.game.items])

    def _remove_key(self):
        for i in self.game.items:
            if i.name == "key":
                self.game.items.remove(i)
                self.game.save_file.save(self.game)
                return

    def _give_key(self):
        self.game.gather_item(Item(
            coords=None, name="key", display_name="Key"))

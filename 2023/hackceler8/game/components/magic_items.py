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

import dill

import pytiled_parser
from enum import Enum
from engine import generics
from engine import hitbox
from os.path import exists


def _get_tileset(name):
    path = "resources/objects/items/%s.tmx" % name
    if not exists(path):
        return "resources/objects/placeholder_item.tmx"
    return path


class Item(generics.GenericObject):
    def __init__(self, coords, name, display_name, color=None, wearable=False):
        if coords is None:  # Placeholder values for items not on the map.
            coords = pytiled_parser.OrderedPair(0, 0)
        self.perimeter = [
            hitbox.Point(coords.x, coords.y),
            hitbox.Point(coords.x + 10, coords.y),
            hitbox.Point(coords.x + 10, coords.y - 10),
            hitbox.Point(coords.x, coords.y - 10),
        ]
        super().__init__(coords, "Item", _get_tileset(name), self.perimeter)
        self.blocking = True
        self.name = name
        self.display_name = display_name
        self.color = color
        self.wearable = wearable
        self.worn = False
        self.collectable = True

        if self.sprite is not None:
            w, h = self.sprite.get_dimensions()
            self._update([
                hitbox.Point(coords.x - w / 2, coords.y - h / 2),
                hitbox.Point(coords.x + w / 2, coords.y - h / 2),
                hitbox.Point(coords.x + w / 2, coords.y + h / 2),
                hitbox.Point(coords.x - w / 2, coords.y + h / 2),
            ])

    def tick(self):
        super().tick()
        # Can't collect items while they're on spikes.
        self.collectable = True
        rect = self.get_rect()
        for o in self.game.objects:
            if o.nametype == "Spike" and o.on and rect.collides(o.get_rect()):
                self.collectable = False

    def _dump(self):
        return dill.dumps([self.nametype, self.name, self.display_name, self.color,
                           self.wearable, str(
            self.collected_time)])

    def is_identical(self, item_compared):
        return all([self.name == item_compared.name, self.display_name ==
                    item_compared.display_name, self.color == item_compared.color,
                    self.wearable == item_compared.wearable])


def load_from_save(name, display_name, color, wearable, collected_time):
    it = Item(None, name, display_name, color, wearable)
    it.collected_time = collected_time
    return it

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
import logging
from os.path import exists
from typing import TYPE_CHECKING

from game.engine import generics
from game.engine import hitbox
from game.engine.point import Point

if TYPE_CHECKING:
    from game.venator import Venator

def _get_image(name: str):
    if name.startswith("coin_"):
        return 'resources/objects/items/coin.png'
    path = 'resources/objects/items/%s.png' % name
    if not exists(path):
        return 'resources/objects/placeholder_item.png'
    return path


class Item(generics.GenericObject):
    game: Venator

    def __init__(self, coords, name, display_name):
        if coords is None:  # Placeholder values for items not on the map.
            coords = Point(0, 0)
        rect = hitbox.Rectangle(coords.x, coords.x + 10, coords.y - 10, coords.y)
        super().__init__(coords, 'Item', _get_image(name), rect)
        self.name = name
        self.display_name = display_name
        self.worn = False
        self.collectable = True

        if self.sprite is not None:
            w, h = self.sprite.get_dimensions()
            rect = hitbox.Rectangle(
                coords.x - w / 2, coords.x + w / 2,
                coords.y - h / 2, coords.y + h / 2
            )
            self.update_hitbox(rect)

    def on_player_collision(self, _player):
        if not self.collectable:
            return
        logging.info(f"Player collected new item {self.name}")
        self.game.gather_item(self)

    def dump(self):
        return {
            'name': self.name,
            'display_name': self.display_name,
            'collected_time': self.collected_time,
        }

    def is_identical(self, item_compared):
        return all([
            self.name == item_compared.name,
            self.display_name == item_compared.display_name,
        ])


def load_items_from_save(items_state):
    items = []
    for i in items_state:
        it = Item(None, i["name"], i["display_name"],)
        it.collected_time = float(i["collected_time"])
        items.append(it)
    return items


def check_item_loaded(items: list[Item], item) -> bool:
    if item is None:
        return False
    for i in items:
        if i.is_identical(item):
            return True
    return False


def display_to_name(display: str) -> str:
    return "".join([c for c in display if (c.isalnum() or c == " ")]).lower().replace(" ", "_")

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

from engine import generics
from engine import hitbox
from components.magic_items import Item


class Duck(generics.GenericObject):

    def __init__(self, coords, name, duck_id):
        self.perimeter = [
            hitbox.Point(coords.x, coords.y),
            hitbox.Point(coords.x + 48, coords.y),
            hitbox.Point(coords.x + 48, coords.y - 48),
            hitbox.Point(coords.x, coords.y - 48),
        ]
        super().__init__(coords, "Duck", None, self.perimeter, name=name)

        self.visited = False
        self.blocking = False
        self.duck_id = duck_id

        self.item_yielded = False

    def yield_item(self):
        if not self.item_yielded:
            return Item(None, "Placeholder", "Placeholder", "violet", True)

    @classmethod
    def stop_item_dropping(cls):
        cls.item_yielded = True

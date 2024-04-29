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
from components import magic_items
from engine import generics
from engine import hitbox


class Door(generics.GenericObject):
    def __init__(self, coords, name):
        self.perimeter = [
            hitbox.Point(coords.x - 32, coords.y - 32),
            hitbox.Point(coords.x + 32, coords.y - 32),
            hitbox.Point(coords.x + 32, coords.y + 32),
            hitbox.Point(coords.x - 32, coords.y + 32),
        ]
        self.unlocker = name[len("door_"):]
        super().__init__(
            coords, "Door", "resources/objects/door/%s.tmx" % self.unlocker,
            self.perimeter, name)
        self.blocking = True

    def passthrough(self, item_list):
        for i in item_list:
            if i.color == self.unlocker:
                return True
        return False

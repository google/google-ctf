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


class Wall(generics.GenericObject):

    def __init__(self, coords, x1, x2, y1, y2, name):
        rect = hitbox.Rectangle(x1, x2, y1, y2)
        super().__init__(coords, "Wall", None, rect, blocking=True)
        self.name = name

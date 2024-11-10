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
from game.engine import modifier


class Ouch(generics.GenericObject):

    def __init__(self, coords, size, min_distance, damage):
        rect = hitbox.Rectangle(coords.x, coords.x + size.width, coords.y - size.height, coords.y)
        super().__init__(coords, "Ouch", None, rect)
        self.modifier = modifier.HealthDamage(
            min_distance=min_distance, damage=damage
        )
        self.name = "Ouch"


class SpikeOuch(generics.GenericObject):

    def __init__(self, coords, size, min_distance, damage):
        rect = hitbox.Rectangle(coords.x, coords.x + size.width, coords.y - size.height, coords.y)
        super().__init__(coords, "SpikeOuch", None, rect)
        self.modifier = modifier.HealthDamage(
            min_distance=min_distance, damage=damage
        )
        self.name = "SpikeOuch"

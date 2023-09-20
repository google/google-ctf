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

from engine import generics
from engine import hitbox
from engine import modifier


class Ouch(generics.GenericObject):
    def __init__(self, coords, size, min_distance, damage):
        self.perimeter = [
            hitbox.Point(coords.x, coords.y),
            hitbox.Point(coords.x + size.width, coords.y),
            hitbox.Point(coords.x + size.width, coords.y - size.height),
            hitbox.Point(coords.x, coords.y - size.height),
        ]
        super().__init__(coords, "Ouch", None, self.perimeter)
        self.modifier = modifier.HealthDamage(min_distance=min_distance, damage=damage)
        self.name = "Ouch"

# Ouch but with blocking spikes in scroller
class SpikeOuch(generics.GenericObject):
    def __init__(self, coords, size, min_distance, damage):
        self.perimeter = [
            hitbox.Point(coords.x, coords.y),
            hitbox.Point(coords.x + size.width, coords.y),
            hitbox.Point(coords.x + size.width, coords.y - size.height),
            hitbox.Point(coords.x, coords.y - size.height),
        ]
        super().__init__(coords, "SpikeOuch", None, self.perimeter)
        self.modifier = modifier.HealthDamage(min_distance=min_distance, damage=damage)
        self.name = "SpikeOuch"

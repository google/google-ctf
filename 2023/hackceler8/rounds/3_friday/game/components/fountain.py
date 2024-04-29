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
from engine import modifier
from engine import hitbox


class Fountain(generics.GenericObject):
    def __init__(self, coords, min_distance):
        super().__init__(coords, "Fountain", "resources/objects/fire.tmx")
        self.modifier = modifier.HealthIncreaser(min_distance=min_distance, benefit=0.5)
        self.sprite.set_animation("idle")
        self.name = "Fire"


class OneTimeFountain(generics.GenericObject):
    def __init__(self, coords, size, min_distance, benefit):
        benefit = 1000
        self.perimeter = [
            hitbox.Point(coords.x, coords.y),
            hitbox.Point(coords.x + size.width, coords.y),
            hitbox.Point(coords.x + size.width, coords.y - size.height),
            hitbox.Point(coords.x, coords.y - size.height),
        ]
        super().__init__(coords, "OneTimeFountain", None, self.perimeter)
        self.modifier = modifier.OneTimeHealthIncreaser(min_distance=min_distance, benefit=benefit)
        self.benefit = benefit
        self.name = "OneTimeFountain"

    def reset(self):
        self.modifier.benefit = self.benefit

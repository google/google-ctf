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

class Modifier:
    def __init__(self, min_distance: int, variable: bool):
        self.min_distance = min_distance
        self.variable = variable

    def calculate_effect(self, effect, distance):
        if not self.variable:
            return effect
        if self.min_distance == 0:
            self.min_distance = 1
        return abs((self.min_distance - distance) / self.min_distance * effect)


class HealthDamage(Modifier):
    def __init__(self, min_distance, damage):
        super().__init__(min_distance, True)
        self.damage = damage


class HealthIncreaser(Modifier):
    def __init__(self, min_distance, benefit):
        super().__init__(min_distance, True)
        self.benefit = benefit

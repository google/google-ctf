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

from game.components.weapon.weapon import Weapon


class Pencil(Weapon):
    def __init__(self, coords, name):
        super().__init__(
            coords=coords,
            name=name,
            display_name="Pencil",
            tileset_path="resources/objects/weapons/pencil.png",
        )

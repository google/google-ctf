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

from game.engine import generics
from game.engine.keys import Keys
from game.components.gems_collection import GemNode


class Gem(generics.GenericObject):
    def __init__(self, coords):
        super().__init__(
            coords=coords,
            name="gem",
            nametype="gem",
            tileset_path="resources/objects/items/gem.png",
        )

        self.game = None

    def on_player_collision(self, _player):
        if self.game.gem_collection is None:
            return
        self.game.gem_collection.add_gem(GemNode("newgem"))
        logging.info("Collected a new gem")
        if self in self.game.objects:
            self.game.objects.remove(self)
        self.game.physics_engine.remove_generic_object(self)

# Copyright 2022 Google LLC
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

import persistent_state
from gametree import *
import os


class HomewardBucket(Component):

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.coordinates = {}
        self.map = None

    def on_use(self):
        map_name = os.path.basename(environ.game.tmx_map.map_file)
        coordinates = self.coordinates.get(map_name, None)
        if coordinates is None:
            self.coordinates[map_name] = Vector2f(
                environ.game.player.transform.position.x, environ.game.player.transform.position.y)
            print("Coordinates memorized.")
            return

        environ.game.player.transform.position.x = coordinates.x
        environ.game.player.transform.position.y = coordinates.y
        self.coordinates[map_name] = None

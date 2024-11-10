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
import logging


class Piquackso(generics.GenericObject):
    def __init__(self, coords):
        rect = hitbox.Rectangle(coords.x, coords.x + 32, coords.y - 105, coords.y)
        super().__init__(coords, "Piquackso", None, rect)
        self.name = "Piquackso"
        self.game = None
        self.commands = []

    def start(self):
        logging.info("Parsing created image")
        output = self.game.painting_system.execute()
        output = output[::-1]
        for o in output:
            for i in range(20):
                self.commands.append(o)
        logging.info(f"Have a total of {len(self.commands)} commands")

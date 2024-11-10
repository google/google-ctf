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

import logging

from game.engine import generics


class StatefulObject(generics.GenericObject):
    def draw(self):
        self.draw()

    def __init__(self, coords, tileset_path, name, ):
        super().__init__(
            coords,
            nametype="Stateful",
            tileset_path=tileset_path,
            name=name,
            can_flip=True,
        )

    def tick(self):
        super().tick()


class Crops(StatefulObject):
    def __init__(self, coords):
        super().__init__(
            coords=coords,
            tileset_path="resources/objects/fire.h8t",
            name="crops"
        )
        self.size = 0

    def tick(self):
        super().tick()
        self.size += 0.1
        if self.size == 10:
            logging.info(self.size)


class Ashek:
    def __init__(self):
        self.ticks = 0
        self.current = "tick"

    def tick(self):
        self.ticks += 1
        self.current = "tick" if self.ticks % 20 else "tock"

    def check(self):
        return self.current
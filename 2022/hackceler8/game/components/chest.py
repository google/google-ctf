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

from typing import Optional

from gametree import *


def gen_framesets():
    return {
    "open":  Frameset(frameset="open"),
    "closed":  Frameset(frameset="closed"),
    }

class Chest(Component):
    additional_framesets = gen_framesets()

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # This is initially None, we then grab the corresponding status from
        # the tile that is actually on the map, i.e. its frameset.
        self.status: Optional[str] = None

    def update_animation(self, frameset):
        if self.entity.frameset != frameset:
            self.entity.frameset = frameset

    def tick(self):
        pass

    def while_keys_held(self, keys):
        pass

    def on_activation(self, caller):
        self.status = "closed" if self.status == "open" else "open"
        self.update_animation(self.status)

    def on_collision_enter(self, other):
        pass

    def while_colliding(self, other):
        pass

    def on_collision_exit(self, other):
        pass

    def duplicate(self, new_entity):
        ret = self.__class__()
        ret.status = self.status
        return ret

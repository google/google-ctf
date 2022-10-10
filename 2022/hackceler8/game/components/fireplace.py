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

from gametree import *


def gen_framesets():
    return {
        "fireplace_on":  Frameset(frameset="fireplace_on"),
        "fireplace_off":  Frameset(frameset="fireplace_off"),
    }


class Fireplace(Component):
    additional_framesets = gen_framesets()

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # This is initially None, we then grab the corresponding status from
        # the tile that is actually on the map, i.e. its frameset.
        self.status = None

    def update_animation(self, frameset):
        if frameset != self.entity.frameset:
            self.entity.frameset = frameset

    def tick(self):
        pass

    def while_keys_held(self, keys):
        pass

    def on_activation(self, caller):
        if self.status == "fireplace_on":
            self.status = "fireplace_off"
        else:
            self.status = "fireplace_on"

        self.update_animation(self.status)

        return

    def on_collision_enter(self, other):
        pass

    def while_colliding(self, other):
        pass

    def on_collision_exit(self, other):
        pass

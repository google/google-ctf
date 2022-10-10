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
        "grate_door_closed": Frameset(frameset="grate_door_closed"),
        "grate_door_open": Frameset(frameset="grate_door_open"),
    }


class GrateDoor(Component):
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
        if hasattr(self, "locked") and self.locked:
            return

        if self.status != "grate_door_closed":
            self.status = "grate_door_closed"
        else:
            self.status = "grate_door_open"

        self.update_animation(self.status)

    def on_collision_enter(self, other):
        pass

    def while_colliding(self, other):
        pass

    def on_collision_exit(self, other):
        pass

class InventoryControlledDoor(GrateDoor):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.item = None
        self.require_item = False
        self.forbid_item = False

    def tick(self):
        if self.require_item and self.forbid_item:
            raise RuntimeError("InventoryControlledDoor may not be set to require + forbid item at the same time.")

        player_has_item = self.item.id in [i.entity.id for i in environ.game.player.inventory]

        if (self.forbid_item and player_has_item) or (self.require_item and not player_has_item):
            self.status = "grate_door_open"
        else:
            self.status = "grate_door_closed"

        self.update_animation(self.status)


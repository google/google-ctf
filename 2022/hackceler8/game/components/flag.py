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
import persistent_state
import time


def gen_framesets():
    ret = {}
    for color in ["red", "orange", "green", "teal", "blue", "purple", "white"]:
        for state in ["unobtained", "obtained"]:
            ret[color + "_" + state] = Frameset(frameset=color + "_" + state)
    return ret


class Flag(Component):
    additional_framesets = gen_framesets()

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.status = "unobtained"
        self.color = None

    def added(self):
        self.color, self.status = self.entity.original_frameset.split("_")

    def update_animation(self, frameset):
        if frameset != self.entity.frameset:
            self.entity.frameset = frameset

    def tick(self):
        if persistent_state.persistent_state.obtained_flags.get(self.color, None):
            self.status = "obtained"
        else:
            self.status = "unobtained"

        self.update_animation(self.color + "_" + self.status)

    def while_keys_held(self, keys):
        pass

    def on_activation(self, caller):
        if self.status != "obtained":
            self.status = "obtained"
            persistent_state.persistent_state.obtained_flags[self.color] = time.time()

        self.entity.frameset = self.color + "_" + self.status

    def on_collision_exit(self, other):
        pass

def gen_podium_framesets():
    ret = {}
    for i in range(0, 64):
        name = f"win_podium_{i}"
        ret[name] = Frameset(frameset=name)
    return ret

class WinPodium(Component):
    additional_framesets = gen_podium_framesets()
    def __init__(self):
        super().__init__()
        self.num_flags_got = 0

        self.red_enabled = False
        self.purple_enabled = False
        self.blue_enabled = False
        self.teal_enabled = False
        self.green_enabled = False
        self.orange_enabled = False

        self.force_update = False

    def added(self):
        self.force_update = True

    def update_frameset(self):
        bitmask = self._calc_bitmask()
        self.entity.frameset = f"win_podium_{bitmask}"
        self.force_update = False

    def tick(self):
        if not persistent_state.persistent_state_ready():
            return

        # TODO(ipudney): Do this check with the persistent state sentinel maybe
        num_flags_got = 0
        for color, got in persistent_state.persistent_state.obtained_flags.items():
            if got:
                num_flags_got += 1
        if self.force_update or self.num_flags_got != num_flags_got:
            self.update_frameset()

    def on_activation(self):
        self.update_frameset()
        if self._calc_bitmask() == 0:
            persistent_state.persistent_state.game_complete = time.time()

    def _calc_bitmask(self):
        bitmask = 63
        for color, got in persistent_state.persistent_state.obtained_flags.items():
            if not got:
                continue
            if color == "red":
                bitmask -= 4
            if color == "purple":
                bitmask -= 2
            if color == "blue":
                bitmask -= 1
            if color == "teal":
                bitmask -= 32
            if color == "green":
                bitmask -= 16
            if color == "orange":
                bitmask -= 8

        # This enables any colors that aren't active this game.
        if not self.red_enabled and "red" not in persistent_state.persistent_state.obtained_flags:
            bitmask -= 4
        if not self.purple_enabled and "purple" not in persistent_state.persistent_state.obtained_flags:
            bitmask -= 2
        if not self.blue_enabled and "blue" not in persistent_state.persistent_state.obtained_flags:
            bitmask -= 1
        if not self.teal_enabled and "teal" not in persistent_state.persistent_state.obtained_flags:
            bitmask -= 32
        if not self.green_enabled and "green" not in persistent_state.persistent_state.obtained_flags:
            bitmask -= 16
        if not self.orange_enabled and "orange" not in persistent_state.persistent_state.obtained_flags:
            bitmask -= 8

        return bitmask
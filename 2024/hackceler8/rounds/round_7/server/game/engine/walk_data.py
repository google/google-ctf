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

from game import constants


class WalkData:
    WALK_SPEED = 100  # 100 pixels per frame

    def __init__(self, obj, data_str):
        self.obj = obj
        self.data = []
        self.walk_progress = 0
        self.walk_speed = WalkData.WALK_SPEED
        if len(data_str) == 0:
            return

        # Load the walking pattern of the NPC from a string
        # e.g. N100,E100: Walk 100px north, then 100px east.
        direction = None
        for d in data_str.split(","):
            direction = d[0]
            if direction in ["N", "E", "S", "W"]:
                self.data.append((direction, int(d[1:])))
            else:
                self.data.append(int(d))  # Sleep for N ms

    def reset(self):
        self.walk_progress = 0

    def walk(self, game):
        if len(self.data) == 0:
            return None
        # Walk around: First find the current walk step
        i = 0
        progress = self.walk_progress
        while True:
            dur = self._get_walk_duration(self.data[i])
            if progress <= dur:
                break
            progress -= dur
            i += 1
            if i >= len(self.data):  # Loops
                i = 0
                self.walk_progress -= sum(
                    [self._get_walk_duration(w) for w in self.data]
                )
        # Then progress the current step (and possibly next ones).
        delta = constants.TICK_S
        last_dir = None
        while True:
            dur = self._get_walk_duration(self.data[i]) - progress
            if delta <= dur:
                last_dir = self._walk(self.data[i], delta)
                break
            last_dir = self._walk(self.data[i], dur)
            progress = 0
            delta -= dur
            i = (i + 1) % len(self.data)  # Loops
        self.walk_progress += constants.TICK_S
        return last_dir

    def _get_walk_duration(self, walk_step):
        if not isinstance(walk_step, tuple):  # Sleep for N ms
            return walk_step / 1000
        # Move N px
        px = walk_step[1]
        return px / self.walk_speed

    def _walk(self, walk_step, dur):
        if not isinstance(walk_step, tuple):
            # Stand still
            return "I"
        # Walk
        dist = dur * self.walk_speed
        match walk_step[0]:
            case "N":
                self.obj.move(0, dist)
            case "E":
                self.obj.move(dist, 0)
            case "S":
                self.obj.move(0, -dist)
            case "W":
                self.obj.move(-dist, 0)
        return walk_step[0]

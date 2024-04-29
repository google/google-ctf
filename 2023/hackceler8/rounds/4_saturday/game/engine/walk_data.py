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

import constants
import logging
import random


class WalkData:
    WALK_SPEED = 100  # 100 pixels per second

    def __init__(self, obj, data_str):
        self.obj = obj
        self.data = []
        self.det_data = []
        self.walk_progress = 0
        self.rng = None
        if len(data_str) == 0:
            return

        # Load the walking pattern of the NPC from a string
        # e.g. N100,E100: Walk 100px north, then 100px east.
        direction = None
        for d in data_str.split(","):
            direction = d[0]
            if direction in ["N", "E", "S", "W", "R"]:
                self.data.append((direction, int(d[1:])))
            else:
                self.data.append(int(d))  # Sleep for N ms

    def reset(self):
        self.walk_progress = 0
        self.det_data = []

    def walk(self, game):
        if len(self.data) == 0:
            return None
        if self.rng is None:
            self.rng = game.rng_system.get("prng")
        if len(self.det_data) == 0:
            self._init_det_data()
        # Walk around: First find the current walk step
        i = 0
        progress = self.walk_progress
        while True:
            dur = self._get_walk_duration(self.det_data[i])
            if progress <= dur:
                break
            progress -= dur
            i += 1
            if i >= len(self.det_data):  # Loops
                i = 0
                self.walk_progress -= sum(
                    [self._get_walk_duration(w) for w in self.det_data])
                self._init_det_data()  # Re-randomize
        # Then progress the current step (and possibly next ones).
        delta = constants.TICK_S
        last_dir = None
        while True:
            dur = self._get_walk_duration(self.det_data[i]) - progress
            if delta <= dur:
                last_dir = self._walk(self.det_data[i], delta)
                break
            last_dir = self._walk(self.det_data[i], dur)
            progress = 0
            delta -= dur
            i = (i + 1) % len(self.det_data)  # Loops
        self.walk_progress += constants.TICK_S
        return last_dir

    def _init_det_data(self):
        self.det_data = []
        for walk_step in self.data:
            if not isinstance(walk_step, tuple):
                self.det_data.append(walk_step)
            elif walk_step[0] == "R":  # Random direction
                self.det_data.append(
                    (self.rng.choice(["N", "E", "S", "W"]),
                     walk_step[1]))
            else:
                self.det_data.append(walk_step)

    def _get_walk_duration(self, walk_step):
        if not isinstance(walk_step, tuple):  # Sleep for N ms
            return walk_step / 1000
        # Move N px
        px = walk_step[1]
        return px / self.WALK_SPEED

    def _walk(self, walk_step, dur):
        if not isinstance(walk_step, tuple):
            # Stand still
            return "I"
        # Walk
        dist = dur * self.WALK_SPEED
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

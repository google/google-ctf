import logging
from typing import Iterable

from game import constants

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

from game.engine import gfx

BLINK_SPEED = 100


class Animation:

    def __init__(self, name: str, blinking: bool, flashing: bool, tileset, textures: list[gfx.TextureReference]):
        self.name = name
        self.blinking = blinking
        self.flashing = flashing
        self.frames = None
        self.frame_starts = []
        self.loop = False
        self.from_frame = 0
        self.cur_frame = 0
        self.cur_time = 0
        self.textures = textures
        for a in tileset.anims:
            if a["name"] == name:
                self.frames = a["frames"]
                self.loop = a.get("loop", False)
                sum_duration = 0
                for f in self.frames:
                    self.frame_starts.append(sum_duration)
                    sum_duration += f["duration"]
                break
        if self.frames is None:
            # No animation set, just show the first tile forever
            self.frames = [{"id": 0, "duration": 1000}]
            self.frame_starts = [0]
            self.loop = True
        self.last_time = self.frame_starts[-1] + self.frames[-1]["duration"]

    def tick(self):
        self.cur_time += constants.TICK_S * 1000
        next_frame = self.cur_frame + 1
        try:
            if next_frame >= len(self.frames):
                if self.loop:
                    if self.cur_time < self.last_time:  # Last frame not done yet
                        return
                    next_frame = 0
                    self.cur_time -= self.last_time
                else:
                    return  # Freeze at the last frame
            if self.frame_starts[next_frame] <= self.cur_time:
                self.cur_frame = next_frame
        except Exception as e:
            logging.error(f"Error during animation: {e}")

    def get_draw_info(self, x, y, scale=1.0, alpha=255) -> Iterable[gfx.SpriteDrawParams]:
        if self.blinking and (self.cur_time // BLINK_SPEED) % 2 == 0:
            return []
        return [gfx.SpriteDrawParams(flashing=self.flashing, x=x, y=y, scale=scale, alpha=alpha,
                                     tex=self.textures[int(self.frames[self.cur_frame]["id"])])]

    def finished(self) -> bool:
        if self.loop:
            return False
        return self.cur_time >= self.last_time

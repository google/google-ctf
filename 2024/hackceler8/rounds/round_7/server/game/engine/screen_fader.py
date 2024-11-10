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
from game.engine import gfx


# Stores state info for the fade-in/out effect for e.g. switching between maps.
class ScreenFader:

  def __init__(self, switch_fun, done_fun):
    self.switch_fun = switch_fun
    self.done_fun = done_fun
    self.fade_in = True
    self.alpha = 0
    self.layer = None

  def tick(self):
    step = int(255 / constants.FADE_DURATION)
    if self.fade_in:
      self.alpha = min(255, self.alpha + step)
      if self.alpha == 255:
        self.fade_in = False
        self.switch_fun()
    else:
      self.alpha = max(0, self.alpha - step)
      if self.alpha == 0:
        self.done_fun()

  def draw(self):
    if not self.layer:
      self.layer = gfx.ShapeLayer()
    self.layer.clear()
    self.layer.add(gfx.lrtb_rectangle_filled(
      0,
      constants.SCREEN_WIDTH,
      constants.SCREEN_HEIGHT,
      0,
      (0, 0, 0, self.alpha),
    ))
    self.layer.build()
    self.layer.draw()

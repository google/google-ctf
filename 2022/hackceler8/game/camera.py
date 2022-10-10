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

import arcade
import math
from pyglet.math import Mat4, Vec3

from typing import Optional


class TargetCamera(arcade.Camera):
    """A camera that maintains display of a particular amount of area around a point, regardless of window size or
       viewport settings. Use .target_area to set the area size."""
    def __init__(self, viewport_width: int = 0, viewport_height: int = 0, window: Optional["arcade.Window"] = None, target_area: int = None):
        super().__init__(viewport_width, viewport_height, window)
        self.target_area = target_area or (viewport_width * viewport_height)
        self.initial_viewport_width = viewport_width
        self.initial_viewport_height = viewport_height
        self.scaling = 1

    def update(self):
        super().update()
        mat = Mat4.from_translation(
            Vec3(
                (self.position[0] - self.viewport_width / 2) * 2 / self.viewport_width,
                (self.position[1] - self.viewport_height / 2) * 2 / self.viewport_height,
                 0))
        self.view_matrix = ~mat

        area = self.viewport_width * self.viewport_height
        self.scaling = math.sqrt(area / self.target_area)
        self.view_matrix @= Mat4().scale(Vec3(self.scaling, self.scaling, 1))

        self.combined_matrix = self.projection_matrix @ self.view_matrix

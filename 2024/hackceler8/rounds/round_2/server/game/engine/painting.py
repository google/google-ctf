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
from typing import Tuple, TYPE_CHECKING
import numpy as np
from PIL import Image

from game.engine import gfx
from game.engine.keys import Keys
from interpreter import piet_interpreter

if TYPE_CHECKING:
    from game.venator import Venator


class ColorDot:
    def __init__(self, point: Tuple[int, int], color_id: int):
        self.point = point
        self.color_id = color_id

COLORS = [
            (255, 192, 192), #salmon
            (255, 0, 0), # red
            (192, 0, 0), # dark red
            (255, 255, 192), #sand
            (255, 255, 0), #yello
            (192, 192, 0), #gold
            (192, 255, 192),
            (0, 255, 0),
            (0, 192, 0),
            (192, 255, 255),
            (0, 255, 255),
            (0, 192, 192),
            (192, 192, 255),
            (0, 0, 255),
            (0, 0, 192),
            (255, 192, 255),
            (255, 0, 255),
            (192, 0, 192),
            (255, 255, 255),
            (0, 0, 0),
        ]

class PaintingSystem:
    def __init__(self, game: 'Venator', dot_size: int = 20):
        self.game = game
        self.current_color = 0
        self.dot_size = dot_size

        self.all_colors = COLORS
        self.current_color = 0
        self.colors = {}
        self.colors_flattened: list[ColorDot] = []
        self.cache: list[tuple[list[tuple[int, int]], tuple[int, int, int]]] = []
        self.x_min = None
        self.y_min = None
        self.x_max = None
        self.y_max = None
        if self.game:
            if not self.game.is_server:
                self.layer = gfx.ShapeLayer()

    def tick(self, newly_pressed_keys):
        if (
                self.game.player is not None
                and self.game.painting_enabled
                and Keys.SPACE in newly_pressed_keys
        ):
            scale = self.dot_size

            x = int(self.game.player.x)
            x = x - x % scale

            if self.x_min is None or x < self.x_min:
                self.x_min = x
            if self.x_max is None or x > self.x_max:
                self.x_max = x

            y = int(self.game.player.y)
            y = y - y % scale

            if self.y_min is None or y < self.y_min:
                self.y_min = y
            if self.y_max is None or y > self.y_max:
                self.y_max = y

            if x not in self.colors.keys():
                self.colors[x] = {}
            old = self.colors[x].get(y, None)
            if old is None:
                color_dot = ColorDot((x, y), self.current_color)
                self.colors[x][y] = color_dot
                self.colors_flattened.append(color_dot)
            else:
                color_id = old.color_id
                color_id += 1
                if color_id >= len(self.all_colors):
                    color_id = 0
                old.color_id = color_id
                self.current_color = color_id

            self.cache = []
            for i, color in enumerate(self.all_colors):
                points = [
                    dot.point for dot in self.colors_flattened if dot.color_id == i
                ]
                if points:
                    self.cache.append((points, color))

    def draw(self):
        if self.cache:
            self.layer.clear()
            for points, color in self.cache:
                for p in points:
                    self.layer.add(gfx.rectangle_filled(p[0], p[1], self.dot_size, self.dot_size, color + (255,)))
            self.layer.build()
            self.layer.draw()

    def execute(self):
        if not self.cache:
            return
        structured_code = self._to_image()
        try:
            _p = piet_interpreter.PietInterpreter(image=structured_code)

            _p.run()
            return _p.command_string
            logging.info(f"Executing the following commands{_p.command_string}")

        except Exception as e:
            logging.critical(f"Failed to interpret code: {e}")

    def _to_image(self) -> np.ndarray:
        if not self.cache:
            return np.zeros((0, 0, 3), np.uint8)

        width = int(self.x_max / self.dot_size) - int(self.x_min / self.dot_size) + 1
        height = int(self.y_max / self.dot_size) - int(self.y_min / self.dot_size) + 1

        logging.info(f"Exporting image with dimensions (w, h): {width, height}")

        image = np.zeros((height, width, 3), dtype=np.uint8)

        for points, color in self.cache:
            for point in points:
                x, y = point
                x = int((x - self.x_min) / self.dot_size)
                y = int((y - self.y_min) / self.dot_size)

                if 0 <= x < width and 0 <= y < height:
                    image[y, x] = color

        im = Image.fromarray(image)
        return image

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
import numpy as np
from PIL import Image

from interpreter.run import interpret


class MercyInterpreter:
    def to_image(self, cache, x_min, x_max, y_min, y_max, dot_size) -> np.ndarray:
        width = int(x_max / dot_size) - int(x_min / dot_size) + 1
        height = int(y_max / dot_size) - int(y_min / dot_size) + 1

        logging.info(f"Exporting image with dimensions (w, h): {width, height}")

        image = np.zeros((height, width, 3), dtype=np.uint8)

        for points, color in cache:
            for point in points:
                x, y = point
                x = int((x - x_min) / dot_size)
                y = int((y - y_min) / dot_size)

                if 0 <= x < width and 0 <= y < height:
                    image[y, x] = color

        im = Image.fromarray(image)
        im.save('test.png')
        open('test', 'w').write(str(image))

        try:
            interpret(image)
            interpret(self.simplified_hello_world())
        except Exception as e:
            logging.critical(e)

    @staticmethod
    def simplified_hello_world():
        colors = {
            'white': [255, 255, 255],  # No-op
            'black': [0, 0, 0],  # Block, cannot enter
            'red_light': [255, 192, 192],
            'red_normal': [255, 0, 0],  # Push operation
            'red_dark': [192, 0, 0],  # Addition
            'yellow_light': [255, 255, 192],
            'yellow_normal': [255, 255, 0],
            'yellow_dark': [192, 192, 0],
            'green_light': [192, 255, 192],
            'green_normal': [0, 255, 0],  # Subtraction
            'green_dark': [0, 192, 0],
            'cyan_light': [192, 255, 255],
            'cyan_normal': [0, 255, 255],  # Duplicate
            'cyan_dark': [0, 192, 192],  # Input
            'blue_light': [192, 192, 255],
            'blue_normal': [0, 0, 255],  # Output character
            'blue_dark': [0, 0, 192],
            'magenta_light': [255, 192, 255],
            'magenta_normal': [255, 0, 255],  # Modulus
            'magenta_dark': [192, 0, 192]
        }

        # Creating a 96x33 numpy array to hold RGB values for each codel (piet program size)
        image = np.zeros((33, 96, 3), dtype=np.uint8)

        # Initialize with white (background)
        image[:, :] = colors['white']

        # Now we'll fill the array with blocks of colors corresponding to "Hello, World!"
        # For simplicity, we push each character's ASCII value, then output.

        # Row 1: Push 'H' (72 in ASCII)
        image[1:3, 1:6] = colors['red_normal']  # Push operation (light red region)
        image[3:5, 1:6] = colors['blue_normal']  # Output operation (light blue region)

        # Continue for each letter in "Hello, World!"

        # Push 'e' (101 in ASCII)
        image[5:7, 1:6] = colors['red_normal']  # Push operation for 'e'
        image[7:9, 1:6] = colors['blue_normal']  # Output operation for 'e'

        # Push 'l' (108 in ASCII)
        image[9:11, 1:6] = colors['red_normal']  # Push operation for 'l'
        image[11:13, 1:6] = colors['blue_normal']  # Output operation for 'l'

        # Push 'l' (again)
        image[13:15, 1:6] = colors['red_normal']  # Push operation for 'l'
        image[15:17, 1:6] = colors['blue_normal']  # Output operation for 'l'

        # Push 'o' (111 in ASCII)
        image[17:19, 1:6] = colors['red_normal']  # Push operation for 'o'
        image[19:21, 1:6] = colors['blue_normal']  # Output operation for 'o'

        # Push ',' (44 in ASCII)
        image[21:23, 1:6] = colors['red_normal']  # Push operation for ','
        image[23:25, 1:6] = colors['blue_normal']  # Output operation for ','

        # Push ' ' (32 in ASCII)
        image[25:27, 1:6] = colors['red_normal']  # Push operation for space
        image[27:29, 1:6] = colors['blue_normal']  # Output operation for space

        # Push 'W' (87 in ASCII)
        image[29:31, 1:6] = colors['red_normal']  # Push operation for 'W'
        image[31:33, 1:6] = colors['blue_normal']  # Output operation for 'W'

        return image

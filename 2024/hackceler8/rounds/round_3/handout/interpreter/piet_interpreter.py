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

import numpy as np
from PIL import Image
from collections import deque

import logging

from game.engine.keys import Keys

# Piet color definitions (as RGB tuples)
piet_colors = {
    (255, 192, 192): 'light_red', (255, 0, 0): 'normal_red', (192, 0, 0): 'dark_red',
    (255, 255, 192): 'light_yellow', (255, 255, 0): 'normal_yellow', (192, 192, 0): 'dark_yellow',
    (192, 255, 192): 'light_green', (0, 255, 0): 'normal_green', (0, 192, 0): 'dark_green',
    (192, 255, 255): 'light_cyan', (0, 255, 255): 'normal_cyan', (0, 192, 192): 'dark_cyan',
    (192, 192, 255): 'light_blue', (0, 0, 255): 'normal_blue', (0, 0, 192): 'dark_blue',
    (255, 192, 255): 'light_magenta', (255, 0, 255): 'normal_magenta', (192, 0, 192): 'dark_magenta',
    (255, 255, 255): 'white', (0, 0, 0): 'black'
}

# Instruction mapping based on hue and lightness changes
operations = {
    (0, 1): 'push', (0, 2): 'pop', (1, 0): 'add', (1, 1): 'subtract', (1, 2): 'multiply',
    (2, 0): 'divide', (2, 1): 'mod', (2, 2): 'not', (3, 0): 'greater', (3, 1): 'pointer',
    (3, 2): 'switch', (4, 0): 'duplicate', (4, 1): 'roll', (4, 2): 'in_num', (5, 0): 'out_num',
    (5, 1): 'in_char', (5, 2): 'out_char'
}

# Direction Pointer (DP) movement vectors
dp_moves = [(1, 0), (0, -1), (-1, 0), (0, 1)]  # right, down, left, up


def get_operation_key(current_color, next_color):
    hue_change = (list(piet_colors.values()).index(next_color) // 3) - (list(piet_colors.values()).index(current_color) // 3)
    lightness_change = (list(piet_colors.values()).index(next_color) % 3) - (list(piet_colors.values()).index(current_color) % 3)
    operation_key = (hue_change % 6, lightness_change % 3)
    logging.info(operation_key)
    return operation_key


class PietInterpreter:
    def __init__(self, image):
        self.image = np.array(image)
        self.stack = []
        self.dp = 0  # Direction pointer (0: right, 1: down, 2: left, 3: up)
        self.cc = 0  # Codel chooser (0: left, 1: right)
        self.width, self.height = self.image.shape[1], self.image.shape[0]
        self.x, self.y = 0, self.height-1  # Current codel coordinates
        self.command_string = []

    def get_color(self, x, y):
        """Returns the color at position (x, y) in the image."""
        if 0 <= x < self.width and 0 <= y < self.height:
            rgb = tuple(self.image[y, x])
            return piet_colors.get(rgb, 'black')  # Return 'black' for undefined colors
        return 'black'

    def find_block_size(self, start_x, start_y):
        """Finds the size of the codel block starting at (start_x, start_y)."""
        color = self.get_color(start_x, start_y)
        visited = set()
        queue = deque([(start_x, start_y)])
        visited.add((start_x, start_y))

        while queue:
            x, y = queue.popleft()
            # Check the four neighboring cells (up, down, left, right)
            for dx, dy in dp_moves:
                nx, ny = x + dx, y + dy
                if 0 <= nx < self.width and 0 <= ny < self.height and (nx, ny) not in visited:
                    if self.get_color(nx, ny) == color:
                        queue.append((nx, ny))
                        visited.add((nx, ny))

        return len(visited)  # The size of the block

    def move(self):
        """Move the DP to the next codel."""
        dx, dy = dp_moves[self.dp]
        self.x += dx
        self.y += dy

    def push(self, value):
        self.stack.append(value)

    def pop(self):
        if self.stack:
            return self.stack.pop()
        else:
            return 0

    def perform_operation(self, operation):
        logging.info(f"Executing operation {operation}. Stack: {self.stack}")
        if operation == 'push':
            # Calculate the size of the current color block and push it
            block_size = self.find_block_size(self.x, self.y)
            self.push(block_size)
            logging.info(f"Pushed {block_size}")
        elif operation == 'pop':
            self.pop()
        elif operation == 'add':
            a = self.pop()
            b = self.pop()
            self.push(a + b)
            logging.info(f"Added {a} and {b}")
        elif operation == 'subtract':
            a = self.pop()
            b = self.pop()
            self.push(b - a)
        elif operation == 'multiply':
            a = self.pop()
            b = self.pop()
            self.push(a * b)
        elif operation == 'divide':
            a = self.pop()
            b = self.pop()
            if a != 0:
                self.push(b // a)
            else:
                self.push(0)  # Prevent division by zero
        elif operation == 'mod':
            a = self.pop()
            b = self.pop()
            if a != 0:
                self.push(b % a)
            else:
                self.push(0)  # Prevent modulus by zero
        elif operation == 'not':
            self.push(1 if self.pop() == 0 else 0)
        elif operation == 'greater':
            a = self.pop()
            b = self.pop()
            self.push(1 if b > a else 0)
        elif operation == 'duplicate':
            a = self.pop()
            self.push(a)
            self.push(a)
        elif operation == 'pointer':
            a = self.pop()
            olddp=self.dp
            self.dp = (self.dp + a) % 4
            logging.critical(f"DP is now: {self.dp} (was: {olddp})")
        elif operation == 'out_char':
            ch_out = self.stack[-1]
            logging.info(f"Outputting char {ch_out}")
            self.command_string.append(self.translate_me(ch_out))

    @staticmethod
    def translate_me(n):
        match n:
            case 1:
                return Keys.D
            case 2:
                return Keys.A
            case 3:
                return Keys.W
            case 4:
                return Keys.S
            case _:
                return ""
    def run(self):
        """Main interpreter loop."""
        while self.get_color(self.x, self.y) != 'black':
            logging.info(f"Current at coordinates {self.x}, {self.y}")
            current_color = self.get_color(self.x, self.y)
            next_color = self.get_color(self.x + dp_moves[self.dp][0], self.y + dp_moves[self.dp][1])
            logging.info(f"{current_color} --> {next_color} (next coords: {self.y + dp_moves[self.dp][1]})")
            # Determine the hue and lightness changes between current and next colors
            self.move()
            if current_color != 'black' and current_color != 'white':
                operation_key = get_operation_key(current_color, next_color)
                logging.info(operation_key)

                if operation_key in operations:
                    operation = operations[operation_key]
                    self.perform_operation(operation)

if __name__ == "__main__":
    # Load the Piet image
    image_test = Image.open('test2.png')

    # m = MercyInterpreter()
    # test = m.simplified_hello_world()
    # print(test)

    # Create the interpreter and run it
    interpreter = PietInterpreter(image_test)
    interpreter.run()
    print(interpreter.command_string)

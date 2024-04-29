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
import logging
from typing import Optional, Tuple
import time

from arcade import key
from engine import generics
from engine import hitbox
from components.magic_items import Item

from enum import Enum

from ctypes import c_uint8

TICK_GRANULARITY = 5
VALID_KEYS = [1, 2, 3, 4, 5, 6, 7, 8, 9, 62, 60, 46, 44, 43, 45, 91, 93]


class DuckModes(Enum):
    MODE_RECORDING = "recording"
    MODE_EXECUTING = "executing"


class Brainduck(generics.GenericObject):
    order = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9]

    def __init__(self, coords, size, name, max_steps=1000):
        self.perimeter = [
            hitbox.Point(coords.x, coords.y),
            hitbox.Point(coords.x + size.width, coords.y),
            hitbox.Point(coords.x + size.width, coords.y - size.height),
            hitbox.Point(coords.x, coords.y - size.height),
        ]
        super().__init__(coords, "Brainduck", None, self.perimeter)
        self.blocking = False
        self.name = name
        # secrets.seed(seed)
        self.stopped = False
        self.max_steps = max_steps

        # self.interpreter = None

        self.last_press_tics = 0
        self.failed = False
        self.total_steps = 0
        self.instructions = bytearray()
        self.walking_data = None

        self.active = False

        self.tics = 0
        self.recorded_tics = 0
        self.mode = None

        self.start_time = 0

        self.pc = 0

        self.reset()

    def reset(self):
        self.stopped = False
        self.active = False

        self.last_press_tics = 0
        self.failed = False
        self.total_steps = 0
        self.pc = 0
        self.instructions = bytearray()
        self.mode = DuckModes.MODE_RECORDING

    def add_key(self, pressed_keys, newly_pressed_keys):
        self.recorded_tics += 1
        shift = key.LSHIFT in pressed_keys
        pressed = None

        for k in newly_pressed_keys:
            if k != key.LSHIFT:
                pressed = k
                break

        if pressed is None:
            for k in pressed_keys:
                if k != key.LSHIFT:
                    pressed = k
                    break

        if pressed and shift:
            match pressed:
                case key.W:
                    self.instructions.append(43)
                case key.S:
                    self.instructions.append(45)
                case key.D:
                    self.instructions.append(91)
                case key.A:
                    self.instructions.append(93)
        elif pressed:
            match pressed:
                case key.W:
                    self.instructions.append(62)
                case key.S:
                    self.instructions.append(60)
                case key.D:
                    self.instructions.append(46)
                case key.A:
                    self.instructions.append(44)

    def start(self):
        self.start_time = time.time()
        self.mode = DuckModes.MODE_EXECUTING
        self.walking_data = self.bf_to_walk(self.instructions)

    def stop(self):
        self.stopped = True

    def run_to_print(self) -> Optional[int]:
        if self.stopped:
            return

        return self.step_once()

    def bf_to_walk(self, bts):
        return [self.num_to_keys(i) for i in bts]

    def step_once(self) -> Optional[Tuple[int, bool]]:
        if self.pc >= len(self.instructions):
            self.stopped = True
            return None
        else:
            ret = self.num_to_keys(self.instructions[self.pc])
            self.pc += 1
            return ret

    @staticmethod
    def num_to_keys(pressed: int) -> Optional[Tuple[int, bool]]:
        match pressed:
            case 1 | 62:
                return key.W, False
            case 2 | 60:
                return key.S, False
            case 3 | 46:
                return key.D, False
            case 4 | 44:
                return key.A, False
            case 5 | 43:
                return key.W, True
            case 6 | 45:
                return key.S, True
            case 7 | 91:
                return key.D, True
            case 8 | 93:
                return key.A, True
            case other:
                None

    def yield_item(self):
        if not self.item_yielded:
            return Item(None, "Placeholder", "Placeholder", "violet", True)

    def check_order(self, order):
        if order == self.interpreter.order:
            return self.yield_item()
        logging.info(
            f"Wrong order detected (-want + got): {self.interpreter.order, order}")

    def tick(self, pressed_keys, newly_pressed_keys):
        match self.mode:
            case DuckModes.MODE_RECORDING:
                self.add_key(pressed_keys, newly_pressed_keys)
                return "recording"
            case DuckModes.MODE_EXECUTING:
                return self.run_to_print()

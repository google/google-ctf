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

import sys
import copy
import math
import numpy as np
import inspect
from functools import partial

import serialize
from typing import Callable

def module_property(func):
    """Decorator to turn module functions into properties.
    Function names must be prefixed with an underscore."""
    module = sys.modules[func.__module__]

    def base_getattr(name: str) -> Callable:
        raise AttributeError(
            f"module '{module.__name__}' has no attribute '{name}'")

    old_getattr = getattr(module, '__getattr__', base_getattr)

    def new_getattr(name):
        if f'_{name}' == func.__name__:
            return func()
        else:
            return old_getattr(name)

    module.__getattr__ = new_getattr
    return func

def copy_sprite(sprite):
    sprite = copy.copy(sprite)
    sprite._sprite_list = None
    sprite.sprite_lists = []
    return sprite


FLIPPED_HORIZONTALLY_FLAG = 0x80000000
FLIPPED_VERTICALLY_FLAG   = 0x40000000
FLIPPED_DIAGONALLY_FLAG   = 0x20000000

def masked_gid(tile) -> int:
    if not isinstance(tile, int):
        tile = tile.gid
    return tile & 0xfffffff

def is_flipped_horizontally(tile) -> bool:
    if not isinstance(tile, int):
        tile = tile.gid
    return bool(tile & FLIPPED_HORIZONTALLY_FLAG > 0 or tile & FLIPPED_DIAGONALLY_FLAG)

def is_flipped_vertically(tile) -> bool:
    if not isinstance(tile, int):
        tile = tile.gid
    return bool(tile & FLIPPED_VERTICALLY_FLAG > 0 or tile & FLIPPED_DIAGONALLY_FLAG)

def rotate_point(point, center, angle_degrees):
    """
    Rotate a point around a center.
    """
    temp_x = point.x - center.x
    temp_y = point.y - center.y

    angle_radians = math.radians(angle_degrees)
    cos_angle = math.cos(angle_radians)
    sin_angle = math.sin(angle_radians)
    rotated_x = temp_x * cos_angle - temp_y * sin_angle
    rotated_y = temp_x * sin_angle + temp_y * cos_angle

    # translate back
    rounding_precision = 2
    x = round(rotated_x + center.x, rounding_precision)
    y = round(rotated_y + center.y, rounding_precision)

    from gametree import Vector2f
    return Vector2f(x, y)

def rotate_vector(vector, angle_degrees):
    theta = np.deg2rad(angle_degrees)
    rot = np.array([[math.cos(theta), -math.sin(theta)], [math.sin(theta), math.cos(theta)]])
    ret = np.dot(rot, vector)

    from gametree import Vector2f
    return Vector2f(x=ret[0], y=ret[1])

def curry(wrapped_fn, arity=None):
    n_args = len(inspect.getfullargspec(wrapped_fn).args) if arity is None else arity
    def curried(first_arg, *args):
        if n_args == len(args) + 1:
            return wrapped_fn(first_arg, *args)

        return curry(partial(wrapped_fn, first_arg, *args), n_args - (1 + len(args)))
    return curried

def serialize_int(x):
    return (b'+' if x >= 0 else b'-') + (
                abs(x).to_bytes(int(x.bit_length() / 8 + 1), 'little'))


def deserialize_int(x) -> int:
    ret = int.from_bytes(x[1:], "little")
    if x[0] == ord('-'):
        ret *= -1
    return ret

def distance(left_position, right_position):
    return math.sqrt((left_position.x - right_position.x) ** 2 + (left_position.y - right_position.y) ** 2)

def move_towards(position, destination_position, speed):
    import game
    speed *= game.DELTA_TIME

    if distance(position, destination_position) < speed:
        position.x = destination_position.x
        position.y = destination_position.y
        return
    from gametree import Vector2f
    vector = Vector2f(destination_position.x - position.x, destination_position.y - position.y)
    vector = vector / math.sqrt(vector.x ** 2 + vector.y ** 2) * speed
    position.x = position.x + vector.x
    position.y = position.y + vector.y

class Proxy:
    def __init__(self, wrapped):
        # Set attribute via __dict__ to skip the __setattr__ call
        self.__dict__['_wrapped'] = wrapped
    def __getattr__(self, attr):
        attr = self._before_getattr(attr)
        ret = getattr(self._wrapped, attr)
        return self._after_getattr(attr, ret)
    def __setattr__(self, key, value):
        key, value = self._before_setattr(key, value)
        return setattr(self._wrapped, key, value)

    def __len__(self):
        return len(self._wrapped)

    def __getitem__(self, *args):
        args = self._before_getitem(*args)
        ret = self._wrapped.__getitem__(*args)
        return self._after_getitem(ret, *args)
    def __contains__(self, *args):
        return self._wrapped.__contains__(*args)
    def __setitem__(self, *args):
        args = self._before_setitem(*args)
        return self._wrapped.__setitem__(*args)


    def _before_getattr(self, attr):
        return attr
    def _after_getattr(self, attr, ret):
        return ret
    def _before_setattr(self, key, value):
        return (key, value)

    def _before_getitem(self, *args):
        return args
    def _after_getitem(self, ret, *args):
        return ret
    def _before_setitem(self, *args):
        return args

class ModifiedProxy(Proxy):
    def __init__(self, wrapped, modification_sentinel):
        """A Proxy that sets modification_sentinel[0] to True on modification
           to this object or its children."""
        super().__init__(wrapped)
        if not isinstance(modification_sentinel, list):
            raise RuntimeError("modification_sentinel must be a list with a single value.")
        self.__dict__['modification_sentinel'] = modification_sentinel

    def _after_getattr(self, attr, ret):
        if hasattr(ret, "__hash__") and ret.__hash__ != None:
            return ret
        return ModifiedProxy(ret, self.modification_sentinel)

    def _before_setattr(self, key, value):
        import environ
        self.modification_sentinel[0] = environ.game.get_modification_stamp()
        return (key, value)

    def _after_getitem(self, ret, *args):
        if hasattr(ret, "__hash__") and ret.__hash__ != None:
            return ret
        return ModifiedProxy(ret, self.modification_sentinel)

    def _before_setitem(self, *args):
        import environ
        self.modification_sentinel[0] = environ.game.get_modification_stamp()
        return args

class Latch(serialize.SerializableObject):
    """A class for transforming a press-and-hold input into separate on-press and on-release outputs."""
    def __init__(self):
        self.value = False
        self.state = (False, False)

    def update(self, new_value):
        """Call with whether the input is currently held. Returns (on_press, on_release) bool tuple."""
        was_pressed = self.value
        self.value = new_value

        self.state = (self.value and not was_pressed, was_pressed and not self.value)
        return self.state

    @property
    def was_pressed(self):
        return self.state[0]

    @property
    def was_released(self):
        return self.state[1]

class DeterministicRandom(serialize.SerializableObject):
    def __init__(self, seed_bytes):
        h = 1779033703 ^ len(seed_bytes)
        for c in seed_bytes:
            h = ((h ^ c) * 3432918353) & 0xFFFFFFFF
        h = h << 13 | h >> 19
        h = h & 0xFFFFFFFF
        self.h = h

    def deterministic_random(self):
        self.h += 0x6D2B79F5
        t = self.h
        t = ((t ^ (t >> 7)) * (t | 61)) & 0xFFFFFFFF
        t ^= (t + (t ^ (t >> 7)) * (t | 61)) & 0xFFFFFFFF
        return ((t ^ t >> 14) >> 0)

    def fancy_deterministic_random(self):
        import random
        return random.Random(self.deterministic_random())
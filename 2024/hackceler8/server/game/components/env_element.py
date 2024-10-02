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
from game.engine import generics
from game.engine import hitbox


class EnvModifier:

    def __init__(
            self,
            name,
            jump_speed,
            walk_speed,
            gravity,
            jump_override,
    ):
        """:param name: name of the modifier, used in logging

    :param jump_speed: percentage of the jump speed as part of base, float
    :param walk_speed: percentage of the walk speed as part of base, float
    :param gravity: percentage of the gravity as part of base, float
    :param jump_override: whether player is allowed to double jump, bool
    """
        self.name = name
        self.jump_speed = jump_speed
        self.walk_speed = walk_speed
        self.gravity = gravity
        self.jump_override = jump_override


WATER_MODIFIER = EnvModifier("water", 0.7, 0.7, 0.25, True)
CLOUD_MODIFIER_1 = EnvModifier("cloud_1", 1.3, 1, 1, False)
CLOUD_MODIFIER_2 = EnvModifier("cloud_2", 1.7, 1, 1, False)
CLOUD_MODIFIER_3 = EnvModifier("cloud_3", 2.0, 1, 1, False)
ZERO_G_MODIFIER = EnvModifier("zero_g", 2.0, 1, 0, False)

modifiers = {
    "water": WATER_MODIFIER, "cloud_1": CLOUD_MODIFIER_1,
    "cloud_2": CLOUD_MODIFIER_2, "cloud_3": CLOUD_MODIFIER_3, "zero_g": ZERO_G_MODIFIER
}


class EnvElement(generics.GenericObject):

    def __init__(self, coords, x1, x2, y1, y2, name, modifier=None):
        rect = hitbox.Rectangle(x1, x2, y1, y2)
        super().__init__(coords, "Element", None, rect)
        self.name = modifier
        self.modifier = modifiers[modifier]

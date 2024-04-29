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

import colorsys
from collections import deque

import arcade

from engine import generics
from engine import hitbox

LOGIC_COLORS = 9
SPRITE_Y = {
    'Buffer': 0*32,
    'Max': 1*32,
    'Min': 2*32,
    'Add': 3*32,
    'Multiply': 4*32,
    'Invert': 5*32,
    'Negate': 6*32,
    'Subtract': 6*32,
    'Constant': 7*32,
    'Toggle': 8*32,
    'Divide': 9*32,
}

texture_cache = {}

class LogicComponent(generics.GenericObject):
    def __init__(self, coords, logic_id, nametype, init_output, logic_map, outline=None):
        self.logic_map = logic_map
        self.previous_output = init_output
        self.logic_id = logic_id
        if nametype == "LogicDoor":
            tileset_path = None
        else:
            tileset_path = "resources/objects/logic.tmx"
        super().__init__(coords, nametype=nametype, tileset_path=tileset_path, outline=outline)
        if not isinstance(self, PassiveLogicComponent):
            self.update_sprite()

    def texture_index(self):
        if self.previous_output == 0:
            return 0
        else:
            return (self.previous_output-1) % (LOGIC_COLORS-1) + 1

    def update_sprite(self):
        if self.nametype == "LogicDoor":
            return
        self.sprite.set_animation(f"{self.nametype}-{self.texture_index()}")

class PassiveLogicComponent(LogicComponent):
    def __init__(self, coords, logic_id, nametype, init_output, logic_map, outline=None):
        super().__init__(coords, logic_id, nametype, init_output, logic_map, outline)
        if nametype in texture_cache:
            self.textures = texture_cache[nametype]
        else:
            locs = [[i*32, SPRITE_Y[nametype], 32, 32] for i in range(LOGIC_COLORS)]
            self.textures = arcade.load_textures('resources/objects/logic.png', locs, hit_box_algorithm='None')
            texture_cache[nametype] = self.textures
        self.sprite = arcade.Sprite(hit_box_algorithm='None')
        self.sprite.width = 32
        self.sprite.height = 32
        self.sprite.set_position(coords.x, coords.y)
        self.update_sprite()

    def update_sprite(self):
        self.sprite.texture = self.textures[self.texture_index()]

class Buffer(PassiveLogicComponent):
    def __init__(self, coords, logic_id, init_output, logic_map, inp, delay):
        super().__init__(coords, logic_id, "Buffer", init_output, logic_map)
        self.inp = inp
        self.buffer = deque([0]*delay, delay+1)

    def update_output(self):
        self.buffer.appendleft(self.logic_map[self.inp].previous_output)
        return self.buffer.pop()

class Max(PassiveLogicComponent):
    def __init__(self, coords, logic_id, init_output, logic_map, inps):
        super().__init__(coords, logic_id, "Max", init_output, logic_map)
        self.inps = inps

    def update_output(self):
        return max(self.logic_map[inp].previous_output for inp in self.inps)

class Min(PassiveLogicComponent):
    def __init__(self, coords, logic_id, init_output, logic_map, inps):
        super().__init__(coords, logic_id, "Min", init_output, logic_map)
        self.inps = inps

    def update_output(self):
        return min(self.logic_map[inp].previous_output for inp in self.inps)

class Add(PassiveLogicComponent):
    def __init__(self, coords, logic_id, init_output, logic_map, inps, modulus):
        super().__init__(coords, logic_id, "Add", init_output, logic_map)
        self.inps = inps
        self.modulus = modulus

    def update_output(self):
        return sum(self.logic_map[inp].previous_output for inp in self.inps) % self.modulus

class Multiply(PassiveLogicComponent):
    def __init__(self, coords, logic_id, init_output, logic_map, inps, modulus):
        super().__init__(coords, logic_id, "Multiply", init_output, logic_map)
        self.inps = inps
        self.modulus = modulus

    def update_output(self):
        prod = 1
        for inp in self.inps:
            prod *= self.logic_map[inp].previous_output
        return prod % self.modulus

class Invert(PassiveLogicComponent):
    def __init__(self, coords, logic_id, init_output, logic_map, inp, modulus):
        super().__init__(coords, logic_id, "Invert", init_output, logic_map)
        self.inp = inp
        self.modulus = modulus

    def update_output(self):
        return (self.modulus-1) - self.logic_map[self.inp].previous_output

class Negate(PassiveLogicComponent):
    def __init__(self, coords, logic_id, init_output, logic_map, inp, modulus):
        super().__init__(coords, logic_id, "Negate", init_output, logic_map)
        self.inp = inp
        self.modulus = modulus

    def update_output(self):
        return (-self.logic_map[self.inp].previous_output) % self.modulus

class Constant(PassiveLogicComponent):
    def __init__(self, coords, logic_id, logic_map, value):
        super().__init__(coords, logic_id, "Constant", value, logic_map)
        self.value = value

    def update_output(self):
        return self.value

class Toggle(LogicComponent):
    def __init__(self, coords, logic_id, logic_map, init_index, values):
        self.perimeter = [
            hitbox.Point(coords.x - 14, coords.y + 14),
            hitbox.Point(coords.x + 14, coords.y + 14),
            hitbox.Point(coords.x + 14, coords.y - 16),
            hitbox.Point(coords.x - 14, coords.y - 16),
        ]
        super().__init__(coords, logic_id, "Toggle", values[init_index], logic_map, self.perimeter)
        self.values = values
        self.index = init_index

    def update_output(self):
        return self.values[self.index]

    def interact(self):
        self.index = (self.index+1) % len(self.values)

class Subtract(PassiveLogicComponent):
    def __init__(self, coords, logic_id, init_output, logic_map, inps, modulus):
        super().__init__(coords, logic_id, "Subtract", init_output, logic_map)
        self.inps = inps
        self.modulus = modulus

    def update_output(self):
        return (self.logic_map[self.inps[0]].previous_output - self.logic_map[self.inps[1]].previous_output) % self.modulus

class Divide(PassiveLogicComponent):
    def __init__(self, coords, logic_id, init_output, logic_map, inps):
        super().__init__(coords, logic_id, "Divide", init_output, logic_map)
        self.inps = inps

    def update_output(self):
        if self.logic_map[self.inps[1]].previous_output == 0:
            return 0
        return (self.logic_map[self.inps[0]].previous_output // self.logic_map[self.inps[1]].previous_output)

class LogicDoor(LogicComponent):
    def __init__(self, coords, points, logic_id, logic_map, inp):
        self.perimeter = [hitbox.Point(coords.x + p.x, coords.y - p.y) for p in points]
        self.draw_outline = [(p.x,p.y) for p in self.perimeter]
        super().__init__(coords, logic_id, "LogicDoor", 1, logic_map, self.perimeter)
        self.inp = inp
        self.blocking = True
        self.hue = 0

    def update_output(self):
        if self.logic_map[self.inp].previous_output == 0:
            self.blocking = False
        else:
            self.blocking = True
        return self.blocking

    def draw(self):
        color = [int(i*255) for i in colorsys.hsv_to_rgb(self.hue, 0.4, 1)]
        self.hue = (self.hue + 0.01) % 1
        if self.blocking:
            arcade.draw_polygon_filled(self.draw_outline, color)
        else:
            arcade.draw_polygon_outline(self.draw_outline, color, line_width=2)

def parse_logic(props, coords, logic_map, points=None):
    match props["type"]:
        case "Buffer":
            return Buffer(coords, props["logic_id"], int(props["init_output"]), logic_map, props["inp"], int(props["delay"]))
        case "Max":
            return Max(coords, props["logic_id"], int(props["init_output"]), logic_map, props["inps"].split(","))
        case "Min":
            return Min(coords, props["logic_id"], int(props["init_output"]), logic_map, props["inps"].split(","))
        case "Add":
            return Add(coords, props["logic_id"], int(props["init_output"]), logic_map, props["inps"].split(","), int(props["modulus"]))
        case "Multiply":
            return Multiply(coords, props["logic_id"], int(props["init_output"]), logic_map, props["inps"].split(","), int(props["modulus"]))
        case "Invert":
            return Invert(coords, props["logic_id"], int(props["init_output"]), logic_map, props["inp"], int(props["modulus"]))
        case "Negate":
            return Negate(coords, props["logic_id"], int(props["init_output"]), logic_map, props["inp"], int(props["modulus"]))
        case "Subtract":
            return Subtract(coords, props["logic_id"], int(props["init_output"]), logic_map, props["inps"].split(","), int(props["modulus"]))
        case "Divide":
            return Divide(coords, props["logic_id"], int(props["init_output"]), logic_map, props["inps"].split(","))
        case "Constant":
            return Constant(coords, props["logic_id"], logic_map, int(props["value"]))
        case "Toggle":
            return Toggle(coords, props["logic_id"], logic_map, int(props["init_index"]), [int(i) for i in props["values"].split(",")])
        case "LogicDoor":
            return LogicDoor(coords, points, props["logic_id"], logic_map, props["inp"])

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

from collections import deque

from engine import generics
from engine import hitbox

LOGIC_COLORS = 9

class LogicComponent(generics.GenericObject):
    def __init__(self, coords, logic_id, nametype, init_output, logic_map, outline=None):
        self.logic_map = logic_map
        self.previous_output = init_output
        self.logic_id = logic_id
        tileset_path = "resources/objects/logic.tmx"
        super().__init__(coords, nametype=nametype, tileset_path=tileset_path, outline=outline)
        self.update_sprite()

    def update_sprite(self):
        if self.previous_output == 0:
            index = 0
        else:
            index = (self.previous_output-1) % (LOGIC_COLORS-1) + 1
        self.sprite.set_animation(f"{self.nametype}-{index}")

class Buffer(LogicComponent):
    def __init__(self, coords, logic_id, init_output, logic_map, inp, delay):
        super().__init__(coords, logic_id, "Buffer", init_output, logic_map)
        self.inp = inp
        self.buffer = deque([0]*delay, delay+1)

    def update_output(self):
        self.buffer.appendleft(self.logic_map[self.inp].previous_output)
        return self.buffer.pop()

class Max(LogicComponent):
    def __init__(self, coords, logic_id, init_output, logic_map, inps):
        super().__init__(coords, logic_id, "Max", init_output, logic_map)
        self.inps = inps

    def update_output(self):
        return max(self.logic_map[inp].previous_output for inp in self.inps)

class Min(LogicComponent):
    def __init__(self, coords, logic_id, init_output, logic_map, inps):
        super().__init__(coords, logic_id, "Min", init_output, logic_map)
        self.inps = inps

    def update_output(self):
        return min(self.logic_map[inp].previous_output for inp in self.inps)

class Add(LogicComponent):
    def __init__(self, coords, logic_id, init_output, logic_map, inps, modulus):
        super().__init__(coords, logic_id, "Add", init_output, logic_map)
        self.inps = inps
        self.modulus = modulus

    def update_output(self):
        return sum(self.logic_map[inp].previous_output for inp in self.inps) % self.modulus

class Multiply(LogicComponent):
    def __init__(self, coords, logic_id, init_output, logic_map, inps, modulus):
        super().__init__(coords, logic_id, "Multiply", init_output, logic_map)
        self.inps = inps
        self.modulus = modulus

    def update_output(self):
        prod = 1
        for inp in self.inps:
            prod *= self.logic_map[inp].previous_output
        return prod % self.modulus

class Invert(LogicComponent):
    def __init__(self, coords, logic_id, init_output, logic_map, inp, modulus):
        super().__init__(coords, logic_id, "Invert", init_output, logic_map)
        self.inp = inp
        self.modulus = modulus

    def update_output(self):
        return (self.modulus-1) - self.logic_map[self.inp].previous_output

class Negate(LogicComponent):
    def __init__(self, coords, logic_id, init_output, logic_map, inp, modulus):
        super().__init__(coords, logic_id, "Negate", init_output, logic_map)
        self.inp = inp
        self.modulus = modulus

    def update_output(self):
        return (-self.logic_map[self.inp].previous_output) % self.modulus

class Constant(LogicComponent):
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

def parse_logic(props, coords, logic_map, size=None):
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
        case "Constant":
            return Constant(coords, props["logic_id"], logic_map, int(props["value"]))
        case "Toggle":
            return Toggle(coords, props["logic_id"], logic_map, int(props["init_index"]), [int(i) for i in props["values"].split(",")])

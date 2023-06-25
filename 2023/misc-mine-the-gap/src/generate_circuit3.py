#!/usr/bin/env python3

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

from enum import Enum
import sys
import json
import random
from pathlib import Path

def insert_pattern(circuit, pattern, pos, inverts={}, devices={}):
    if type(inverts) == int:
        inverts = {'x': inverts}
    for var in 'xyvwrstu':
        if not inverts.get(var, 0):
            continue
        pattern = pattern.replace(var, 'z').replace(var.upper(), var).replace('z', var.upper())

    for keys, values in devices.items():
        for k, v in zip(keys, values):
            pattern = pattern.replace(k, v)

    assert all(len(line) == len(circuit[0]) for line in circuit)
    pattern_grid = [list(line) for line in pattern.split()]
    assert all(len(line) == len(pattern[0]) for line in pattern)

    start_x, start_y = pos
    for y in range(len(pattern_grid)):
        for x in range(len(pattern_grid[0])):
            circuit[start_y+y][start_x+x] = pattern_grid[y][x]

    return circuit

def load_patterns(patterns_dir):
    return {f.name.rstrip('.txt'): f.read_text() for f in Path(patterns_dir).glob('*.txt')}


def get_input_bits(module):
    input_bits = []
    for _, port in module['ports'].items():
        if port['direction'] != 'input':
            continue

        for bit in port['bits']:
            input_bits.append(bit)
    return input_bits

def calculate_layers(module, input_bits):
    # Parse cells
    wires_available = [set(input_bits)]
    cells_remaining = []
    layers = [[]]
    for cell in module['cells'].values():
        cell_data = {
            'type': cell['type'],
            'inputs': [],
            'outputs': [],
        }
        for conn_name, conn_wires in cell['connections'].items():
            direction = cell['port_directions'][conn_name]
            if direction == 'input':
                cell_data['inputs'] += conn_wires
            elif direction == 'output':
                cell_data['outputs'] += conn_wires
            else:
                print(f'Unknown direction {direction}')

        cells_remaining.append(cell_data)


    # Calculate layers
    current_layer = 1
    previous_wires = set()
    previous_wires |= wires_available[-1]
    wires_available.append(set())

    while len(cells_remaining) > 0:
        next_cell = None
        for cell in cells_remaining:
            if all(x in previous_wires for x in cell['inputs']):
                for x in cell['inputs']:
                    backtrack = 1
                    while x not in wires_available[current_layer-backtrack]:
                        layers[-backtrack-1].append({
                            'type': '$_ID_',
                            'inputs': [x],
                            'outputs': [x],
                        })
                        wires_available[current_layer-backtrack].add(x)
                        backtrack += 1
                next_cell = cell
                break
        else:
            current_layer += 1
            previous_wires |= set(wires_available[-1])
            wires_available.append(set())
            layers.append([])
            continue

        # Add cell to layer
        layers[-1].append(next_cell)

        for out in next_cell['outputs']:
            wires_available[current_layer].add(out)

        cells_remaining.remove(next_cell)

    return layers


def print_layers(layers):
    for i, layer in enumerate(layers):
        layer_inputs = set()
        layer_outputs = set()
        print(f'Layer: {i}', file=sys.stderr)
        for cell in layer:
            layer_inputs |= set(cell['inputs'])
            layer_outputs |= set(cell['outputs'])
            print(cell, file=sys.stderr)

class PortDirection(Enum):
    INPUT = 1
    OUTPUT = 2

class PortOrientation(Enum):
    HORIZONTAL = 1
    VERTICAL = 2

class PortPosition(Enum):
    TOP = 1
    RIGHT = 2
    DOWN = 3
    LEFT = 4

CELL_SIZE = 24

class CircuitCell(object):
    def __init__(self, marker, width, height, x, y):
        self.marker = marker
        # Number of cells
        self.width = width
        self.height = height
        self.x = x
        self.y = y
        # Connectors listed clockwise starting with north face of top-left cell
        self.connectors = [None for _ in range(2*(width+height))]

    def render(self, _patterns, _circuit):
        pass

class InputCellDown(CircuitCell):
    def __init__(self, x, y, out_val):
        assert out_val in [0, 1], out_val
        super().__init__('I', 1, 1, x, y)
        self.connectors[2] = (PortDirection.OUTPUT, out_val)

    def render(self, patterns, circuit):
        circuit = insert_pattern(circuit, patterns['terminal-d'], (self.x * CELL_SIZE + 7, self.y * CELL_SIZE + 21), self.connectors[2][1])

class TerminalCellDown(CircuitCell):
    def __init__(self, x, y, in_val):
        assert in_val in [0, 1], in_val
        super().__init__('T', 1, 1, x, y)
        self.connectors[2] = (PortDirection.INPUT, in_val)

    def render(self, patterns, circuit):
        circuit = insert_pattern(circuit, patterns['terminal-d'], (self.x * CELL_SIZE + 7, self.y * CELL_SIZE + 21), self.connectors[2][1])

class TerminalCellUp(CircuitCell):
    def __init__(self, x, y, in_val):
        assert in_val in [0, 1], in_val
        super().__init__('T', 1, 1, x, y)
        self.connectors[0] = (PortDirection.INPUT, in_val)

    def render(self, patterns, circuit):
        circuit = insert_pattern(circuit, patterns['terminal-u'], (self.x * CELL_SIZE + 7, self.y * CELL_SIZE), 1-self.connectors[0][1])


class TerminalCellRight(CircuitCell):
    def __init__(self, x, y, in_val):
        assert in_val in [0, 1], in_val
        super().__init__('T', 1, 1, x, y)
        self.connectors[1] = (PortDirection.INPUT, in_val)

    def render(self, patterns, circuit):
        circuit = insert_pattern(circuit, patterns['terminal-r'], (self.x * CELL_SIZE + 21, self.y * CELL_SIZE + 12), self.connectors[1][1])


class TerminalCellLeft(CircuitCell):
    def __init__(self, x, y, in_val, forced=False):
        assert in_val in [0, 1], in_val
        super().__init__('T', 1, 1, x, y)
        self.forced = forced
        self.connectors[3] = (PortDirection.INPUT, in_val)

    def render(self, patterns, circuit):
        circuit = insert_pattern(circuit, patterns['terminal-l'], (self.x * CELL_SIZE, self.y * CELL_SIZE + 12), 1-self.connectors[3][1])
        if self.forced:
            circuit[self.y*CELL_SIZE + 14][self.x*CELL_SIZE - 1 + self.connectors[3][1]] = 'M'


class HorizontalWireCell(CircuitCell):
    def __init__(self, x, y, in_val):
        assert in_val in [0, 1], in_val
        super().__init__('W', 1, 1, x, y)
        self.connectors[0] = (PortDirection.INPUT, in_val)
        self.connectors[2] = (PortDirection.OUTPUT, in_val)

    def render(self, patterns, circuit):
        for fill in range(8):
            circuit = insert_pattern(circuit, patterns['wire-ud'], (self.x*CELL_SIZE + 7, self.y*CELL_SIZE + 3*fill), self.connectors[0][1])


class RightSplitCell(CircuitCell):
    def __init__(self, x, y, in_val):
        assert in_val in [0, 1], in_val
        super().__init__('S', 1, 1, x, y)
        self.connectors[0] = (PortDirection.INPUT, in_val)
        self.connectors[1] = (PortDirection.OUTPUT, in_val)
        self.connectors[2] = (PortDirection.OUTPUT, in_val)

    def render(self, patterns, circuit):
        circuit = insert_pattern(circuit, patterns['split-urd'], (self.x * CELL_SIZE + 7 ,      self.y * CELL_SIZE), self.connectors[0][1])
        circuit = insert_pattern(circuit, patterns['turn-ld'],   (self.x * CELL_SIZE + 12 ,     self.y * CELL_SIZE), 1-self.connectors[0][1])
        circuit = insert_pattern(circuit, patterns['not-ud'],    (self.x * CELL_SIZE + 13,  6 + self.y * CELL_SIZE), 1-self.connectors[0][1])
        circuit = insert_pattern(circuit, patterns['turn-ur'],   (self.x * CELL_SIZE + 13, 11 + self.y * CELL_SIZE), 1-self.connectors[0][1])
        circuit = insert_pattern(circuit, patterns['not-lr'],    (self.x * CELL_SIZE + 19, 12 + self.y * CELL_SIZE), self.connectors[0][1])
        circuit = insert_pattern(circuit, patterns['not2-ud'],   (self.x * CELL_SIZE + 7 ,  5 + self.y * CELL_SIZE), self.connectors[0][1])
        circuit = insert_pattern(circuit, patterns['phase-ud'],  (self.x * CELL_SIZE + 7 , 14 + self.y * CELL_SIZE), self.connectors[0][1])
        circuit = insert_pattern(circuit, patterns['wire-ud'],   (self.x * CELL_SIZE + 7 , 21 + self.y * CELL_SIZE), self.connectors[0][1])


class LeftJoinCell(CircuitCell):
    def __init__(self, x, y, in_val):
        assert in_val in [0, 1], in_val
        super().__init__('J', 1, 1, x, y)
        self.connectors[0] = (PortDirection.OUTPUT, in_val)
        self.connectors[2] = (PortDirection.OUTPUT, in_val)
        self.connectors[3] = (PortDirection.INPUT, in_val)


    def render(self, patterns, circuit):
        circuit = insert_pattern(circuit, patterns['turn-lu'],   (self.x * CELL_SIZE    , 11 + self.y * CELL_SIZE), self.connectors[3][1])
        circuit = insert_pattern(circuit, patterns['turn-rd'],   (self.x * CELL_SIZE + 1,  5 + self.y * CELL_SIZE), 1-self.connectors[3][1])
        
        circuit = insert_pattern(circuit, patterns['split-lud'], (self.x * CELL_SIZE + 7,  5 + self.y * CELL_SIZE), 1-self.connectors[3][1])
        
        circuit = insert_pattern(circuit, patterns['not-ud'],    (self.x * CELL_SIZE + 7,      self.y * CELL_SIZE), 1-self.connectors[3][1])
        
        circuit = insert_pattern(circuit, patterns['phase2-ud'], (self.x * CELL_SIZE + 7, 10 + self.y * CELL_SIZE), self.connectors[3][1])
        circuit = insert_pattern(circuit, patterns['wire-ud'],   (self.x * CELL_SIZE + 7, 21 + self.y * CELL_SIZE), self.connectors[3][1])


class CrossingCell(CircuitCell):
    def __init__(self, x, y, in_top, in_left):
        assert in_top in [0, 1], in_top
        assert in_left in [0, 1], in_left
        super().__init__('C', 1, 1, x, y)
        self.connectors[0] = (PortDirection.INPUT, in_top)
        self.connectors[1] = (PortDirection.OUTPUT, in_left)
        self.connectors[2] = (PortDirection.OUTPUT, in_top)
        self.connectors[3] = (PortDirection.INPUT, in_left)

    def render(self, patterns, circuit):
        circuit = insert_pattern(circuit, patterns['phase2-ud'], (self.x*CELL_SIZE +  7,      self.y*CELL_SIZE), self.connectors[0][1])
        circuit = insert_pattern(circuit, patterns['wire-ud'],   (self.x*CELL_SIZE +  7, 21 + self.y*CELL_SIZE), self.connectors[0][1])
        circuit = insert_pattern(circuit, patterns['wire-lr'],   (self.x*CELL_SIZE     , 12 + self.y*CELL_SIZE), 1-self.connectors[3][1])
        circuit = insert_pattern(circuit, patterns['crossing'],  (self.x*CELL_SIZE +  3, 11 + self.y*CELL_SIZE), {'u': 1-self.connectors[0][1], 'v': 1-self.connectors[3][1], 's': 1-self.connectors[0][1], 'r': 1-self.connectors[3][1]})
        circuit = insert_pattern(circuit, patterns['wire-lr'],   (self.x*CELL_SIZE + 21, 12 + self.y*CELL_SIZE), 1-self.connectors[3][1])
        circuit = insert_pattern(circuit, patterns['wire-lr'],   (self.x*CELL_SIZE + 18, 12 + self.y*CELL_SIZE), 1-self.connectors[3][1])


class XorGateCell(CircuitCell):
    def __init__(self, x, y, in_top, in_bottom):
        assert in_top in [0, 1], in_top
        assert in_bottom in [0, 1], in_bottom
        super().__init__('^', 2, 2, x, y)
        self.connectors[3] = (PortDirection.OUTPUT, in_top ^ in_bottom)
        self.connectors[6] = (PortDirection.INPUT, in_bottom)
        self.connectors[7] = (PortDirection.INPUT, in_top)


    def render(self, patterns, circuit):
        circuit = insert_pattern(circuit, patterns['phase-lr'], (self.x*CELL_SIZE, self.y*CELL_SIZE + 36), 1-self.connectors[6][1])
        for fill in range(10):
            circuit = insert_pattern(circuit, patterns['wire-lr'], (self.x*CELL_SIZE + 7 + 3*fill, self.y*CELL_SIZE + 36), 1-self.connectors[6][1])


        for fill in range(10):
            circuit = insert_pattern(circuit, patterns['wire-lr'], (self.x*CELL_SIZE + 3*fill, self.y*CELL_SIZE + 12), 1-self.connectors[7][1])
        circuit = insert_pattern(circuit, patterns['turn-ld'], (self.x*CELL_SIZE + 30, self.y*CELL_SIZE + 12), 1-self.connectors[7][1])
        circuit = insert_pattern(circuit, patterns['phase-ud'], (self.x*CELL_SIZE + 31, self.y*CELL_SIZE + 18), self.connectors[7][1])
        circuit = insert_pattern(circuit, patterns['wire-ud'], (self.x*CELL_SIZE + 31, self.y*CELL_SIZE + 25), self.connectors[7][1])
        circuit = insert_pattern(circuit, patterns['wire-ud'], (self.x*CELL_SIZE + 31, self.y*CELL_SIZE + 28), self.connectors[7][1])
        circuit = insert_pattern(circuit, patterns['turn-ur'], (self.x*CELL_SIZE + 31, self.y*CELL_SIZE + 31), self.connectors[7][1])
        
        if self.connectors[6][1] and self.connectors[7][1]:
            sx = 0
        elif self.connectors[6][1]:
            sx = 1
        else:
            sx = 0

        circuit = insert_pattern(circuit, patterns['xor2-lr'], (self.x*CELL_SIZE + 37, self.y*CELL_SIZE + 26), {'u': 1-self.connectors[6][1], 'v': 1-self.connectors[7][1], 'x': sx, 'w': 1-self.connectors[3][1]})

class AndGateCell(CircuitCell):
    def __init__(self, x, y, in_top, in_bottom):
        assert in_top in [0, 1], in_top
        assert in_bottom in [0, 1], in_bottom
        super().__init__('&', 2, 2, x, y)
        self.connectors[3] = (PortDirection.OUTPUT, in_top & in_bottom)
        self.connectors[6] = (PortDirection.INPUT, in_bottom)
        self.connectors[7] = (PortDirection.INPUT, in_top)


    def render(self, patterns, circuit):
        circuit = insert_pattern(circuit, patterns['turn-lu'],     (self.x*CELL_SIZE     , self.y*CELL_SIZE + 11), self.connectors[7][1])
        circuit = insert_pattern(circuit, patterns['turn-rd'],     (self.x*CELL_SIZE +  1, self.y*CELL_SIZE + 5), 1-self.connectors[7][1])
        circuit = insert_pattern(circuit, patterns['turn-ld'],     (self.x*CELL_SIZE +  7, self.y*CELL_SIZE + 5), 1-self.connectors[7][1])

        r = (1-self.connectors[7][1]) & (1-self.connectors[6][1])
        s = 1 - ((1-self.connectors[7][1]) | (1-self.connectors[6][1]))

        devices = {}
        if self.connectors[3][1]:
            devices['abc'] = '9AA'
            devices['ijk'] = '9AA'
            s = 0
            r = 0
        else:
            if s:
                devices['abc'] = 'AA9'
            else:
                devices['abc'] = 'A9A'

            if r:
                devices['ijk'] = 'AA9'
            else:
                devices['ijk'] = 'A9A'
 

            
        circuit = insert_pattern(circuit, patterns['and-lr'],      (self.x*CELL_SIZE +  8, self.y*CELL_SIZE + 11), {'u': 1-self.connectors[7][1], 'v': 1-self.connectors[6][1], 's': s, 'r': r, 't': 1-self.connectors[3][1]}, devices=devices)

        circuit = insert_pattern(circuit, patterns['phase-lr'],    (self.x*CELL_SIZE     , self.y*CELL_SIZE + 36), 1-self.connectors[6][1])
        circuit = insert_pattern(circuit, patterns['turn-lu'],     (self.x*CELL_SIZE +  7, self.y*CELL_SIZE + 35), self.connectors[6][1])
        for fill in range(3):
            circuit = insert_pattern(circuit, patterns['wire-ud'], (self.x*CELL_SIZE +  8, self.y*CELL_SIZE + 26 + 3*fill), 1-self.connectors[6][1])

        circuit = insert_pattern(circuit, patterns['turn-ld'],     (self.x*CELL_SIZE + 29, self.y*CELL_SIZE + 16), 1-self.connectors[3][1])
        circuit = insert_pattern(circuit, patterns['phase-ud'],    (self.x*CELL_SIZE + 30, self.y*CELL_SIZE + 22), self.connectors[3][1])
        for fill in range(2):
            circuit = insert_pattern(circuit, patterns['wire-ud'], (self.x*CELL_SIZE + 30, self.y*CELL_SIZE + 29 + 3*fill), self.connectors[3][1])
        
        circuit = insert_pattern(circuit, patterns['turn-ur'],     (self.x*CELL_SIZE + 30, self.y*CELL_SIZE + 35), self.connectors[3][1])
        for fill in range(4):
            circuit = insert_pattern(circuit, patterns['wire-lr'], (self.x*CELL_SIZE + 36 + 3*fill, self.y*CELL_SIZE + 36), 1-self.connectors[3][1])
    


class OrGateCell(CircuitCell):
    def __init__(self, x, y, in_top, in_bottom):
        assert in_top in [0, 1], in_top
        assert in_bottom in [0, 1], in_bottom
        super().__init__('|', 2, 2, x, y)
        self.connectors[3] = (PortDirection.OUTPUT, in_top | in_bottom)
        self.connectors[6] = (PortDirection.INPUT, in_bottom)
        self.connectors[7] = (PortDirection.INPUT, in_top)


    def render(self, patterns, circuit):
        circuit = insert_pattern(circuit, patterns['turn-ld'], (self.x*CELL_SIZE, self.y*CELL_SIZE + 12), 1-self.connectors[7][1])
        circuit = insert_pattern(circuit, patterns['wire-ud'], (self.x*CELL_SIZE + 1, self.y*CELL_SIZE + 18), self.connectors[7][1])
        for fill in range(2):
            circuit = insert_pattern(circuit, patterns['phase-ud'], (self.x*CELL_SIZE + 1, self.y*CELL_SIZE + 21 + 7*fill), self.connectors[7][1])

        devices = {}
        if self.connectors[6][1] and self.connectors[7][1]:
            devices['abc'] = 'AA9'
            s = 0
        elif self.connectors[3][1]:
            devices['abc'] = 'A9A'
            s = 1
        else:
            devices['abc'] = '9AA'
            s = 1

        circuit = insert_pattern(circuit, patterns['or-lur'], (self.x*CELL_SIZE, self.y*CELL_SIZE + 35), {'u': 1-self.connectors[7][1], 'v': 1-self.connectors[6][1], 'r': 1-self.connectors[3][1], 's': s}, devices=devices)

        for fill in range(12):
            circuit = insert_pattern(circuit, patterns['wire-lr'], (self.x*CELL_SIZE + 12 + 3*fill, self.y*CELL_SIZE + 36), 1-self.connectors[3][1])


class NotGateCell(CircuitCell):
    def __init__(self, x, y, in_val):
        assert in_val in [0, 1], in_val
        super().__init__('~', 2, 1, x, y)
        self.connectors[2] = (PortDirection.OUTPUT, (~in_val)&1)
        self.connectors[5] = (PortDirection.INPUT, in_val)

    def render(self, patterns, circuit):
        for fill in range(13):
            circuit = insert_pattern(circuit, patterns['wire-lr'], (self.x*CELL_SIZE + 3*fill, self.y*CELL_SIZE + 12), 1-self.connectors[5][1])
        circuit = insert_pattern(circuit, patterns['not2-lr'], (self.x*CELL_SIZE + 39, self.y*CELL_SIZE + 12), self.connectors[2][1])
        

class IdGateCell(CircuitCell):
    def __init__(self, x, y, in_val):
        assert in_val in [0, 1], in_val
        super().__init__('=', 2, 1, x, y)
        self.connectors[2] = (PortDirection.OUTPUT, in_val)
        self.connectors[5] = (PortDirection.INPUT, in_val)

    def render(self, patterns, circuit):
        for fill in range(16):
            circuit = insert_pattern(circuit, patterns['wire-lr'], (self.x*CELL_SIZE + 3*fill, self.y*CELL_SIZE + 12), 1-self.connectors[5][1])
        

def add_cell(cells, cell):
    for dy in range(cell.height):
        for dx in range(cell.width):
            cells[cell.y + dy][cell.x + dx] = cell

def get_port_value(cells, x, y, position):
    cell = cells[y][x]
    dx = x - cell.x
    dy = y - cell.y

    # 1x1 cell
    if cell.width == 1 and cell.height == 1:
        assert dx == 0, dx
        assert dy == 0, dy
        if position == PortPosition.TOP:
            connector = cell.connectors[0]
        elif position == PortPosition.RIGHT:
            connector = cell.connectors[1]
        elif position == PortPosition.DOWN:
            connector = cell.connectors[2]
        elif position == PortPosition.LEFT:
            connector = cell.connectors[3]
        
    # 2x1 cell
    elif cell.width == 2 and cell.height == 1:
        assert dy == 0, dy
        if position == PortPosition.TOP and dx == 0:
            connector = cell.connectors[0]
        elif position == PortPosition.TOP and dx == 1:
            connector = cell.connectors[1]
        elif position == PortPosition.RIGHT and dx == 1:
            connector = cell.connectors[2]
        elif position == PortPosition.DOWN and dx == 1:
            connector = cell.connectors[3]
        elif position == PortPosition.DOWN and dx == 0:
            connector = cell.connectors[4]
        elif position == PortPosition.LEFT and dx == 0:
            connector = cell.connectors[5]
        
    # 2x2 cell
    elif cell.width == 2 and cell.height == 2:
        if position == PortPosition.TOP and dx == 0 and dy == 0:
            connector = cell.connectors[0]
        elif position == PortPosition.TOP and dx == 1 and dy == 0:
            connector = cell.connectors[1]
        elif position == PortPosition.RIGHT and dx == 1 and dy == 0:
            connector = cell.connectors[2]
        elif position == PortPosition.RIGHT and dx == 1 and dy == 1:
            connector = cell.connectors[3]
        elif position == PortPosition.DOWN and dx == 1 and dy == 1:
            connector = cell.connectors[4]
        elif position == PortPosition.DOWN and dx == 0 and dy == 1:
            connector = cell.connectors[5]
        elif position == PortPosition.LEFT and dx == 0 and dy == 1:
            connector = cell.connectors[6]
        elif position == PortPosition.LEFT and dx == 0 and dy == 0:
            connector = cell.connectors[7]
        
    else:
        raise NotImplementedError('Only 1x1, 2x1 and 2x2 cells supported')

    return connector[1]

def print_cells(cells):
    for row in cells:
        for cell in row:
            if cell:
                print(cell.marker, end='')
            else:
                print(' ', end='')
        print()


def render_cells(cells, patterns):
    circuit_width = len(cells[0])*CELL_SIZE
    circuit_height = len(cells)*CELL_SIZE
    circuit = [['0' for _ in range(circuit_width)] for _ in range(circuit_height)]
    for y in range(len(cells)):
        for x in range(len(cells[0])):
            if cells[y][x] and cells[y][x].x == x and cells[y][x].y == y:
                cells[y][x].render(patterns, circuit)

    circuit = '\n'.join(''.join(line) for line in circuit)
    return circuit

patterns = load_patterns('patterns')

input_value = int(sys.argv[1]) if len(sys.argv) > 1 else 219
input_values = [int(x) for x in f'{input_value:08b}']
#input_values = [1,0,1,1, 1,1,0,1]

GRID_WIDTH = 150
GRID_HEIGHT = 68
cells = [[None for _ in range(GRID_WIDTH)] for _ in range(GRID_HEIGHT)]

with open('schematic.json', 'r') as fin:
    schematic = json.load(fin)
module = schematic['modules']['Challenge']
input_bits = get_input_bits(module)
layers = calculate_layers(module, input_bits)
print_layers(layers)

# First bus crosses
channels = []
for cell in layers[0]:
    channels += cell['inputs']

# Add input cells
for x, (wire_name, value) in enumerate(zip(input_bits, input_values)):
    cell = InputCellDown(x, 0, value)
    add_cell(cells, cell)

# Create input bus
y_base = 1
layers_outputs = [{wire: i for i, wire in enumerate(sorted(input_bits))}]
for y, input_name in enumerate(channels):
    for x, (wire_name, value) in enumerate(zip(input_bits, input_values)):
        # UD Wire
        if layers_outputs[0][wire_name] < layers_outputs[0][input_name]:
            cell = HorizontalWireCell(x, y_base + y, value)
        # Split
        elif layers_outputs[0][wire_name] == layers_outputs[0][input_name]:
            cell = RightSplitCell(x, y_base + y, value)
        # Cross
        else:
            cell = CrossingCell(x, y_base + y, value, get_port_value(cells, x-1, y+1, PortPosition.RIGHT))

        add_cell(cells, cell)

# Cap off bottom
y_base = y_base + y + 1
for x, (wire_name, value) in enumerate(zip(input_bits, input_values)):
    cell = TerminalCellUp(x, y_base, value)
    add_cell(cells, cell)
    


# Layer 1
layers_outputs.append({})
x_base = len(input_bits)
y_base = 1
dy = 0
for cell in layers[0]:
    x = x_base
    y = y_base + dy
    if cell['type'] == '$_ID_':
        cell2 = IdGateCell(x, y, get_port_value(cells, x - 1, y, PortPosition.RIGHT))
        dy += 1
    elif cell['type'] == '$_NOT_':
        cell2 = NotGateCell(x, y, get_port_value(cells, x - 1, y, PortPosition.RIGHT))
        dy += 1
    elif cell['type'] == '$_AND_':
        cell2 = AndGateCell(x, y, get_port_value(cells, x - 1, y, PortPosition.RIGHT), get_port_value(cells, x - 1, y + 1, PortPosition.RIGHT))
        dy += 2
    elif cell['type'] == '$_OR_':
        cell2 = OrGateCell(x, y, get_port_value(cells, x - 1, y, PortPosition.RIGHT), get_port_value(cells, x - 1, y + 1, PortPosition.RIGHT))
        dy += 2
    elif cell['type'] == '$_XOR_':
        cell2 = XorGateCell(x, y, get_port_value(cells, x - 1, y, PortPosition.RIGHT), get_port_value(cells, x - 1, y + 1, PortPosition.RIGHT))
        dy += 2

    add_cell(cells, cell2)
    assert len(cell['outputs']) == 1
    layers_outputs[-1][cell['outputs'][0]] = y_base + dy - 1



# Output bus 1
x_base += 2
y_base = 0
wires_seen_y = set()
layer_outputs_inv = {v: k for k, v in layers_outputs[-1].items()}
wire_joins = {}
wire_x_offsets = {}
for dx, (wire_name, wire_y) in enumerate(layers_outputs[-1].items()):
    wire_joins[wire_y] = dx
    wire_x_offsets[wire_name] = dx
    
    wire_val = get_port_value(cells, x_base - 1, wire_y, PortPosition.RIGHT)

    for y in range(67):
        # Split
        if y == wire_y:
            cell = LeftJoinCell(x_base + dx, y_base + y, wire_val)
        # Crossing
        elif y in layer_outputs_inv and y not in wires_seen_y:
            cell = CrossingCell(x_base + dx, y_base + y, wire_val, get_port_value(cells, x_base + dx - 1, y_base + y, PortPosition.RIGHT))
        # UD Wire
        else:
            cell = HorizontalWireCell(x_base + dx, y_base + y, wire_val)
        add_cell(cells, cell)
            
        wires_seen_y.add(wire_y)

    cell = TerminalCellDown(x_base + dx, y_base, get_port_value(cells, x_base + dx, y_base + 1, PortPosition.TOP))
    add_cell(cells, cell)
    cell = TerminalCellUp(x_base + dx, y_base + y + 1, get_port_value(cells, x_base + dx, y_base + y, PortPosition.DOWN))
    add_cell(cells, cell)


#LAST_LAYER = 2
LAST_LAYER = 10
for layer_idx in range(1, LAST_LAYER+1):
    # Input bus 2
    y_base = 1
    y_offset = 0
    cell_offsets = []
    for cell in layers[layer_idx]:
        while True:
            wires_x = [wire_x_offsets[wire_name] for wire_name in cell['inputs']]
            if not any(wire_joins.get(y_base + y_offset + dy, -1) >= wire_x for dy, wire_x in enumerate(wires_x)):
                cell_offsets.append(y_offset)
                break
            y_offset += 1
        
        for wire_name in cell['inputs']:
            x_start = wire_x_offsets[wire_name]
            for x_offset in range(x_start, len(wire_x_offsets)):
                x = x_base + x_offset
                y = y_base + y_offset

                if x_offset == x_start:
                    cell2 = RightSplitCell(x, y, get_port_value(cells, x, y - 1, PortPosition.DOWN))
                else:
                    cell2 = CrossingCell(x, y, get_port_value(cells, x, y - 1, PortPosition.DOWN), get_port_value(cells, x - 1, y, PortPosition.RIGHT))
                add_cell(cells, cell2)

            y_offset += 1

    # Layer 2
    layers_outputs.append({})
    dy = 0
    x_base += len(wire_x_offsets)
    for cell_idx, cell in enumerate(layers[layer_idx]):
        dy = cell_offsets[cell_idx]
        
        x = x_base
        y = y_base + dy
        if cell['type'] == '$_ID_':
            cell2 = IdGateCell(x, y, get_port_value(cells, x - 1, y, PortPosition.RIGHT))
            dy += 1
        elif cell['type'] == '$_NOT_':
            cell2 = NotGateCell(x, y, get_port_value(cells, x - 1, y, PortPosition.RIGHT))
            dy += 1
        elif cell['type'] == '$_AND_':
            cell2 = AndGateCell(x, y, get_port_value(cells, x - 1, y, PortPosition.RIGHT), get_port_value(cells, x - 1, y + 1, PortPosition.RIGHT))
            dy += 2
        elif cell['type'] == '$_OR_':
            cell2 = OrGateCell(x, y, get_port_value(cells, x - 1, y, PortPosition.RIGHT), get_port_value(cells, x - 1, y + 1, PortPosition.RIGHT))
            dy += 2
        elif cell['type'] == '$_XOR_':
            cell2 = XorGateCell(x, y, get_port_value(cells, x - 1, y, PortPosition.RIGHT), get_port_value(cells, x - 1, y + 1, PortPosition.RIGHT))
            dy += 2

        assert len(cell['outputs']) == 1
        add_cell(cells, cell2)
        layers_outputs[-1][cell['outputs'][0]] = y_base + dy - 1

    if layer_idx < LAST_LAYER:
        # Output bus 2
        x_base += 2
        y_base = 0
        wires_seen_y = set()
        layer_outputs_inv = {v: k for k, v in layers_outputs[-1].items()}
        wire_joins = {}
        wire_x_offsets = {}
        for dx, (wire_name, wire_y) in enumerate(layers_outputs[-1].items()):
            wire_joins[wire_y] = dx
            wire_x_offsets[wire_name] = dx

            wire_val = get_port_value(cells, x_base - 1, wire_y, PortPosition.RIGHT)

            for y in range(67):
                # Split
                if y == wire_y:
                    cell = LeftJoinCell(x_base + dx, y_base + y, wire_val)
                # Crossing
                elif y in layer_outputs_inv and y not in wires_seen_y:
                    cell = CrossingCell(x_base + dx, y_base + y, wire_val, get_port_value(cells, x_base + dx - 1, y_base + y, PortPosition.RIGHT))
                # UD Wire
                else:
                    cell = HorizontalWireCell(x_base + dx, y_base + y, wire_val)
                add_cell(cells, cell)
                    
                wires_seen_y.add(wire_y)

            cell = TerminalCellDown(x_base + dx, y_base, get_port_value(cells, x_base + dx, y_base + 1, PortPosition.TOP))
            add_cell(cells, cell)
            cell = TerminalCellUp(x_base + dx, y_base + y + 1, get_port_value(cells, x_base + dx, y_base + y, PortPosition.DOWN))
            add_cell(cells, cell)

x_base += 2

cell = TerminalCellLeft(x_base, y_base + 1, 1, forced=True)
add_cell(cells, cell)


def debug_grid1():

    # And Debug grid
    cells = [[None for _ in range(4)] for _ in range(16)]
    cell = AndGateCell(1, 0, 0, 0)
    add_cell(cells, cell)
    cell = AndGateCell(1, 4, 0, 1)
    add_cell(cells, cell)
    cell = AndGateCell(1, 8, 1, 0)
    add_cell(cells, cell)
    cell = AndGateCell(1, 12, 1, 1)
    add_cell(cells, cell)

    cell = TerminalCellRight(0, 0, 0)
    add_cell(cells, cell)
    cell = TerminalCellRight(0, 1, 0)
    add_cell(cells, cell)
    cell = TerminalCellLeft(3, 1, 0)
    add_cell(cells, cell)

    cell = TerminalCellRight(0, 4, 0)
    add_cell(cells, cell)
    cell = TerminalCellRight(0, 5, 1)
    add_cell(cells, cell)
    cell = TerminalCellLeft(3, 5, 0)
    add_cell(cells, cell)

    cell = TerminalCellRight(0, 8, 1)
    add_cell(cells, cell)
    cell = TerminalCellRight(0, 9, 0)
    add_cell(cells, cell)
    cell = TerminalCellLeft(3, 9, 0)
    add_cell(cells, cell)

    cell = TerminalCellRight(0, 12, 1)
    add_cell(cells, cell)
    cell = TerminalCellRight(0, 13, 1)
    add_cell(cells, cell)
    cell = TerminalCellLeft(3, 13, 1)
    add_cell(cells, cell)
    return cells


def debug_grid2():

    # And Debug grid
    cells = [[None for _ in range(4)] for _ in range(16)]
    cell = OrGateCell(1, 0, 0, 0)
    add_cell(cells, cell)
    cell = OrGateCell(1, 4, 0, 1)
    add_cell(cells, cell)
    cell = OrGateCell(1, 8, 1, 0)
    add_cell(cells, cell)
    cell = OrGateCell(1, 12, 1, 1)
    add_cell(cells, cell)

    cell = TerminalCellRight(0, 0, 0)
    add_cell(cells, cell)
    cell = TerminalCellRight(0, 1, 0)
    add_cell(cells, cell)
    cell = TerminalCellLeft(3, 1, 0)
    add_cell(cells, cell)

    cell = TerminalCellRight(0, 4, 0)
    add_cell(cells, cell)
    cell = TerminalCellRight(0, 5, 1)
    add_cell(cells, cell)
    cell = TerminalCellLeft(3, 5, 1)
    add_cell(cells, cell)

    cell = TerminalCellRight(0, 8, 1)
    add_cell(cells, cell)
    cell = TerminalCellRight(0, 9, 0)
    add_cell(cells, cell)
    cell = TerminalCellLeft(3, 9, 1)
    add_cell(cells, cell)

    cell = TerminalCellRight(0, 12, 1)
    add_cell(cells, cell)
    cell = TerminalCellRight(0, 13, 1)
    add_cell(cells, cell)
    cell = TerminalCellLeft(3, 13, 1)
    add_cell(cells, cell)
    return cells



def debug_grid3():

    # And Debug grid
    cells = [[None for _ in range(4)] for _ in range(16)]
    cell = XorGateCell(1, 0, 0, 0)
    add_cell(cells, cell)
    cell = XorGateCell(1, 4, 0, 1)
    add_cell(cells, cell)
    cell = XorGateCell(1, 8, 1, 0)
    add_cell(cells, cell)
    cell = XorGateCell(1, 12, 1, 1)
    add_cell(cells, cell)

    cell = TerminalCellRight(0, 0, 0)
    add_cell(cells, cell)
    cell = TerminalCellRight(0, 1, 0)
    add_cell(cells, cell)
    cell = TerminalCellLeft(3, 1, 0)
    add_cell(cells, cell)

    cell = TerminalCellRight(0, 4, 0)
    add_cell(cells, cell)
    cell = TerminalCellRight(0, 5, 1)
    add_cell(cells, cell)
    cell = TerminalCellLeft(3, 5, 1)
    add_cell(cells, cell)

    cell = TerminalCellRight(0, 8, 1)
    add_cell(cells, cell)
    cell = TerminalCellRight(0, 9, 0)
    add_cell(cells, cell)
    cell = TerminalCellLeft(3, 9, 1)
    add_cell(cells, cell)

    cell = TerminalCellRight(0, 12, 1)
    add_cell(cells, cell)
    cell = TerminalCellRight(0, 13, 1)
    add_cell(cells, cell)
    cell = TerminalCellLeft(3, 13, 0)
    add_cell(cells, cell)
    return cells

#cells = debug_grid1()
#cells = debug_grid2()
#cells = debug_grid3()
print_cells(cells)

circuit = render_cells(cells, patterns)
circuit = circuit.replace('0', ' ')
circuit = circuit.replace('M', 'B')
circuit = circuit.replace('a', '9')
circuit = circuit.replace('b', '9')

circuit_release = circuit
for var in 'xyvwrstu':
    circuit_release = circuit_release.replace(var, '9')
    circuit_release = circuit_release.replace(var.upper(), '9')
circuit_release = circuit_release.replace('A', '9')

circuit_debug = circuit
for var in 'xyvwrstu':
    circuit_debug = circuit_debug.replace(var, 'A')
    circuit_debug = circuit_debug.replace(var.upper(), '9')

#filename_base = sys.argv[1]
filename_base = 'gameboard'
with open(f'{filename_base}.txt', 'w') as fout:
    fout.write(circuit_release)

with open(f'{filename_base}-debug.txt', 'w') as fout:
    fout.write(circuit_debug)


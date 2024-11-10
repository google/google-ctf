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

from game.engine.painting import COLORS
from interpreter.piet_interpreter import get_operation_key, operations, piet_colors


def get_color_simple(color):
    for k,v in piet_colors.items():
        if v == color:
            return k

def get_step_count(color_0, color_1):
    color_0_value = get_color_simple(color_0)
    color_1_value = get_color_simple(color_1)
    c0_pos = COLORS.index(color_0_value)
    c1_pos = COLORS.index(color_1_value)
    # print(c0_pos)
    # print(c1_pos)
    total_positions = len(COLORS)
    steps = (c1_pos - c0_pos) % total_positions
    # print(steps)
    return steps+1

def get_operation(color_0, target_operation):
    # _colors = PaintingSystem(game=None).all_colors
    for _c in piet_colors.values():
        op = get_operation_key(color_0, _c)
        if op in operations:
            _operation = operations[op]
            if _operation == target_operation:
                # print(f"FOund it with color {_c}")
                stps = get_step_count(color_0, _c)
                return _c, stps

tmplt = '''
    replay.enqueue(increase)

    for i in range({stps}):
        replay.enqueue(go_next_color)
'''

walk_tmlt = '''    
    for i in range({stps}):
        replay.enqueue(draw_one_left)
'''

program = ['duplicate', 'add', 'duplicate', 'add', 'duplicate', 'add', 'duplicate', 'add', 'duplicate', 'add', 'duplicate', 'add', 'duplicate', 'duplicate', 'add',
           'push', #push 1 so now we are at [128,1]
           'duplicate', 'add','duplicate', 'add','duplicate', 'multiply',
            'subtract', 'duplicate','out_char', # at this point stack is [64,112] and we've outputed 'p'
           'walk_7','push','subtract','duplicate', 'out_char', # at this point stack is [64,105] and we've outputed 'pi'
           'walk_3', 'push', 'subtract', 'walk_2', 'push', 'divide', 'duplicate', 'out_char', #[64, 51]
           'add', 'push','add', 'duplicate', 'out_char', # [116]
           'walk_2', 'push', 'duplicate', 'add', 'duplicate', 'add', 'duplicate', 'add', 'walk_5', 'push', 'add', 'subtract', 'duplicate', 'out_char', # [95]
            'walk_3', 'push', 'add', 'walk_2', 'push', 'divide', 'duplicate', 'duplicate','out_char', # [49]
           'duplicate', 'add', 'walk_6', 'push','duplicate','duplicate','add','add','add', 'duplicate', 'push','subtract', 'out_char', #[49, 116]
           'pop','duplicate','add','walk_3','push','subtract','duplicate', 'out_char', # [95]
           'walk_7', 'push', 'add', 'walk_2', 'push', 'divide', 'duplicate', 'out_char', # [51],
           'walk_1', 'push','add', 'duplicate', 'out_char', #52
           'walk_1','push','duplicate', 'add','duplicate', 'add', 'duplicate', 'add','add','walk_2','push','multiply','duplicate','walk_2', 'push', 'add', 'out_char',
           'push', 'add', 'out_char'
           ]

prog_string = ''

if __name__ == '__main__':
    tmp = 'normal_red'
    for i in program:
        if i.startswith('walk'):
            stps = int(i.split('_')[1])
            prog_string += walk_tmlt.format(stps=stps-1)
        else:
            tmp, stps = get_operation(tmp, i)
            prog_string += tmplt.format(stps=stps)

    print(prog_string)

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
    for k, v in piet_colors.items():
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
    return steps + 1


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
replay.enqueue({draw_dir})

for i in range({stps}):
    replay.enqueue(go_next_color)
'''
draw_arr = ["draw_one_left", "draw_one_down", "draw_one_right", "draw_one_up"]
increase_arr = ["increase_left", "increase_down", "increase_right", "increase_up"]
walk_tmlt = '''    
for i in range({stps}):
    replay.enqueue({draw_dir})
'''

# program = ['out_char','out_char','out_char','out_char','out_char','out_char','out_char','out_char','out_char',
#            'walk_2', 'push', 'add','out_char','out_char','out_char','walk_2', 'push', 'subtract', 'out_char','out_char','out_char','out_char','out_char',
#             'out_char','out_char','out_char','walk_3','push','add','out_char','out_char','out_char','out_char','push','pointer'
#            ]
dirs = [0, 1, 2, 3]  # right, 1 is down, 2 is left, 3 is up
dir = dirs[0]
program = ['out_char', 'out_char', 'out_char', 'push', 'push', 'add', 'push', 'add', 'out_char', 'out_char', 'out_char', 'push', 'out_char', 'out_char', 'out_char', 'out_char', 'out_char', 'out_char', 'out_char', 'pointer',
           'push', 'push', 'add', 'duplicate', 'add', 'out_char', 'out_char', 'out_char', 'out_char', 'push', 'out_char', 'out_char', 'out_char', 'pointer',
           'push', 'out_char', 'out_char', 'out_char', 'out_char', 'out_char', 'out_char', 'out_char', 'out_char', 'out_char', 'push', 'add', 'duplicate', 'add', 'out_char', 'out_char', 'out_char', 'out_char', 'push', 'pointer',
           'push', 'out_char', 'out_char', 'out_char', 'out_char', 'out_char', 'out_char', 'out_char', 'out_char', 'push', 'pointer',
           'push', 'out_char', 'out_char', 'out_char', 'out_char', 'out_char', 'out_char', 'out_char', # until here it works then we get assed
           'out_char','out_char', 'out_char', 'out_char', 'out_char', 'out_char', 'out_char','out_char', 'out_char', 'push', 'pointer',
           'push', 'out_char', 'out_char', 'out_char', 'out_char', 'pointer','pop', 'subtract', 'out_char', 'out_char', 'out_char', 'out_char','push', 'out_char','out_char'
           #'push','out_char', 'out_char', 'out_char', 'out_char', 'out_char', 'out_char'
           # 'pointer',
           # 'push', 'out_char','out_char', 'out_char','out_char', 'out_char', 'out_char'
           ]

prog_string = ''


def blockify(arr, n):
    return [arr[i:i + n] for i in range(0, len(arr), n)]


if __name__ == '__main__':
    tmp = 'normal_red'
    curr_dir = 0
    curr_draw = draw_arr[curr_dir]
    curr_increase = increase_arr[curr_dir]
    curr_row = 0
    max_length = 20
    # if program > max_length:
    #     initial = program[:max_length-1]
    #
    for i in program:
        if i.startswith('walk'):
            stps = int(i.split('_')[1])
            prog_string += walk_tmlt.format(stps=stps - 1, draw_dir=curr_draw)
        else:
            tmp, stps = get_operation(tmp, i)
            prog_string += tmplt.format(stps=stps, draw_dir=curr_increase)

        if i == 'pointer':
            curr_dir = (curr_dir + 1) % 4
            curr_draw = draw_arr[curr_dir]
            curr_increase = increase_arr[curr_dir]

    print(prog_string)
    open('piet_prog_str', 'w').write(prog_string)

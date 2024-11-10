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

from poc.helper import ReplayHelper
import logging


# def draw_canvas(replay):


def replay_iter_func(replay):
    draw_one_left = ['d'] * 20 + [' ']
    increase_left = ['d'] * 20
    increase_down = ['s'] * 20
    increase_right = ['a'] * 20
    increase_up = ['w'] * 20
    draw_one_right = ['a'] * 20 + [' ']
    draw_one_up = ['w'] * 20 + [' ']
    draw_one_down = ['s'] * 20 + [' ']
    go_next_color = [''] + [' ']


    start_stars = replay.game.match_flags.stars()
    logging.info("Entering new map")
    replay.enter_map("maze")
    replay.teleport(65, 83)
    # replay.enqueue(['a'] * 2 + [' '])
    # yield

    replay.enqueue([' ']*100)
    yield

    # for i in range(20):
    #     replay.enqueue(['d'] * 1 + [' '])
    #
    for i in range(2):
        replay.enqueue(draw_one_left)

    replay.enqueue(go_next_color)

    prog = open('poc/piet_prog_str').read()
    exec(prog)

    ## Start prog
    # replay.enqueue(increase)
    #
    # for i in range(15):
    #     replay.enqueue(go_next_color)
    #
    # replay.enqueue(increase)
    #
    # for i in range(20):
    #     replay.enqueue(go_next_color)
    #
    # replay.enqueue(increase)
    #
    # for i in range(17):
    #     replay.enqueue(go_next_color)
    #
    # replay.enqueue(increase)
    #
    # for i in range(17):
    #     replay.enqueue(go_next_color)
    #
    # replay.enqueue(increase)
    #
    # for i in range(20):
    #     replay.enqueue(go_next_color)
    #
    # replay.enqueue(increase)
    #
    # for i in range(17):
    #     replay.enqueue(go_next_color)
    #
    # replay.enqueue(increase)
    #
    # for i in range(15):
    #     replay.enqueue(go_next_color)
    #
    # replay.enqueue(increase)
    #
    # for i in range(20):
    #     replay.enqueue(go_next_color)
    #
    # replay.enqueue(increase)
    #
    # for i in range(17):
    #     replay.enqueue(go_next_color)
    #
    # for i in range(1):
    #     replay.enqueue(draw_one_left)
    #
    # replay.enqueue(increase)
    #
    # for i in range(2):
    #     replay.enqueue(go_next_color)
    #
    # replay.enqueue(increase)
    #
    # for i in range(4):
    #     replay.enqueue(go_next_color)
    #
    # replay.enqueue(increase)
    #
    # for i in range(17):
    #     replay.enqueue(go_next_color)
    #
    # replay.enqueue(increase)
    #
    # for i in range(17):
    #     replay.enqueue(go_next_color)
    #
    # replay.enqueue(increase)
    #
    # for i in range(20):
    #     replay.enqueue(go_next_color)
    #
    # replay.enqueue(increase)
    #
    # for i in range(17):
    #     replay.enqueue(go_next_color)
    #
    # for i in range(1):
    #     replay.enqueue(draw_one_left)
    #
    # replay.enqueue(increase)
    #
    # for i in range(2):
    #     replay.enqueue(go_next_color)
    #
    # replay.enqueue(increase)
    #
    # for i in range(2):
    #     replay.enqueue(go_next_color)
    #
    # replay.enqueue(increase)
    #
    # for i in range(20):
    #     replay.enqueue(go_next_color)
    #
    # replay.enqueue(increase)
    #
    # for i in range(15):
    #     replay.enqueue(go_next_color)
    #
    # replay.enqueue(increase)
    #
    # for i in range(17):
    #     replay.enqueue(go_next_color)
    #
    # replay.enqueue(increase)
    #
    # for i in range(20):
    #     replay.enqueue(go_next_color)




    # replay.enqueue(increase)
    #
    # for i in range(2):
    #     replay.enqueue(go_next_color)
    #
    # replay.enqueue(increase)
    #
    # for i in range(15):
    #     replay.enqueue(go_next_color)
    # replay.enqueue(go_next_color)
    # replay.enqueue(['']*1000)
    yield
    replay.teleport(945, 496)
    # Game state assertions
    for i in range(660):
        replay.enqueue(['e'] + [''])
    yield
    assert not replay.game.player.dead
    assert replay.game.match_flags.stars() > start_stars
    replay.exit()


if __name__ == '__main__':
    replay = ReplayHelper()
    replay.start_game(replay_iter_func)


## I ain't no chump so had this done by chatty
"""
// Start by initializing the stack with a base value, we start at 0.
push            // Push 0 onto the stack

// Build 112 ('p'): We can reach 112 by multiplying smaller values.
increment       // 1
duplicate       // 1, 1
add             // 1 + 1 = 2
duplicate       // 2, 2
add             // 2 + 2 = 4
duplicate       // 4, 4
add             // 4 + 4 = 8
duplicate       // 8, 8
add             // 8 + 8 = 16
duplicate       // 16, 16
add             // 16 + 16 = 32
duplicate       // 32, 32
add             // 32 + 32 = 64
duplicate       // 64, 64
add             // 64 + 64 = 128
push            // Push 128 onto the stack
increment       // 129
substract       // 129 - 17 = 112 ('p')
print           // Print 'p'

// Build 105 ('i'): We can duplicate 112 and subtract 7.
duplicate       // 112, 112
push            // Push the duplicated 112
increment       // Increment for subtraction
increment
increment
increment
increment
increment
increment       // Increment 7 times
substract       // Subtract 7 to get 105 ('i')
print           // Print 'i'

// Build 51 ('3'): We can use the original 64, subtract 13.
duplicate       // 64, 64
push            // Push 64 onto stack
substract       // 64 - 13 = 51 ('3')
print           // Print '3'

// Build 116 ('t'): We can reuse 112 and increment by 4.
duplicate       // 112, 112
push            // Push 112 onto stack
increment       // Increment 4 times
increment
increment
increment
add             // 112 + 4 = 116 ('t')
print           // Print 't'

// Build 95 ('_'): We will subtract 17 from 112 to get 95.
duplicate       // 112, 112
push            // Push 112 onto stack
substract       // 112 - 17 = 95 ('_')
print           // Print '_'

// Build 49 ('1'): We can reuse 51 and subtract 2.
duplicate       // 51, 51
push            // Push 51 onto stack
substract       // 51 - 2 = 49 ('1')
print           // Print '1'

// Build 115 ('s'): We can duplicate 116 and subtract 1.
duplicate       // 116, 116
push            // Push 116 onto stack
substract       // 116 - 1 = 115 ('s')
print           // Print 's'

// Build 95 ('_'): Use the previous 95 directly.
duplicate       // 95, 95
push            // Push 95 onto stack
print           // Print '_'

// Build 51 ('3'): Use the previous 51 directly.
duplicate       // 51, 51
push            // Push 51 onto stack
print           // Print '3'

// Build 52 ('4'): Increment the previous 51 by 1.
duplicate       // 51, 51
increment       // Increment 1
push            // 51 + 1 = 52 ('4')
print           // Print '4'

// Build 122 ('z'): Add 6 to 116.
duplicate       // 116, 116
increment       // Increment 6 times
increment
increment
increment
increment
increment
push            // 116 + 6 = 122 ('z')
print           // Print 'z'

// Build 121 ('y'): Subtract 1 from 122.
duplicate       // 122, 122
substract       // 122 - 1 = 121 ('y')
print           // Print 'y'

"""

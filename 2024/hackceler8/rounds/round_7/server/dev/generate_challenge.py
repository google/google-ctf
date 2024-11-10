#!/usr/bin/env python
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

"""
Please don't tell anyone how I code
"""
import random

next_obj_id = 29
def format_enemy(x, y, walk):
    global next_obj_id
    if walk == '':
        return ""
    next_obj_id = next_obj_id + 1
    return f"""
  <object id="{next_obj_id - 1}" name="siren_enemy" x="{x}" y="{y}">
   <properties>
    <property name="damage" type="float" value="1000"/>
    <property name="walk_data" value="{walk}"/>
   </properties>
   <point/>
  </object>"""

TILE_SZ = 64

# Sirens have melee range of 70, so we need to stay lower than that (+hitboxsz) to avoid safe zones
ENEMY_W = 100
# We can't make this too small otherwise the player does not have enough time to "swap" between groups.
ENEMY_H = ENEMY_W

def one_way_circle(sx, sy, l, free_spots = None):
    start_pos_x = sx#750
    start_pos_y = sy#4448

    one_way_len = l#5
    one_way_width = (one_way_len - 1) * ENEMY_W

    free_spots = [] if free_spots is None else free_spots

    xml = []

    # In addition to the one_way_len - 1 enemies, we need one_way_len additional ones
    for enemy_id in range(2 * one_way_len):
        if enemy_id in free_spots:
            continue
        if enemy_id < one_way_len:
            offset = enemy_id * ENEMY_W
            enemy_pos_x = start_pos_x + (enemy_id + 1) * ENEMY_W
            enemy_pos_y = start_pos_y
            instructions = [
                # Move to the right
                f"E{one_way_width - offset}",
                # Move up
                f"N{ENEMY_H}",
                f"W{one_way_width}",
                f"S{ENEMY_H}",

                # Move back to our starting position
                f"E{offset}",
            ]
        else:
            # position of enemy_id == one_way_len should be exactly the same as for one_way_len - 1
            # -> enemy_id * tile_sz => one_way_len * tile_sz
            offset = (2 * one_way_len - enemy_id) * ENEMY_W
            enemy_pos_x = start_pos_x + offset
            enemy_pos_y = start_pos_y - 1 * ENEMY_H
            instructions = [
                # Move to the left
                f"W{offset - ENEMY_W}",
                f"S{ENEMY_H}",
                f"E{one_way_width}",
                f"N{ENEMY_H}",
                f"W{one_way_width + ENEMY_W - offset}",
            ]

        xml.append(format_enemy(enemy_pos_x, enemy_pos_y, ','.join(instructions)))

    return ''.join(xml)

circles = [
    (5, [0, 1, 2, 5, 6, 7], 5),
    (5, [0, 1, 2], 5),
    (7, [10, 11], 0),
    (7, [0, 1, 3, 4], 0),
    (7, [9, 10, 11,  6, 7], 0),
    (7, [0, 1], 0)
]

xml = []
pos_x = 450
cycle_offset = 0
for (order, free_spots, offset_i) in circles:
    free_spots = [ (i + cycle_offset) % (2 * order) for i in free_spots ]
    xml.append(one_way_circle(pos_x, 4448, order, free_spots))
    pos_x = pos_x + order * ENEMY_W
    cycle_offset = cycle_offset + offset_i

with open('template.tmx', 'r') as f:
    foo = f.read().replace('$PLACEHOLDER$', ''.join(xml))

with open('resources/levels/ocean/ocean_lvl.tmx', 'w') as f:
    f.write(foo)

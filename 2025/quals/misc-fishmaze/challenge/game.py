# Copyright 2025 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# -*- coding: utf-8 -*-
"""FishMaze.py

"""

import jax
from jax import export
import jax.numpy as jnp
from jax.experimental import pallas as pl
from jax.experimental.pallas import tpu as pltpu
from jax import lax
import time
import numpy as np
import tempfile
import json
from scipy.stats import norm
from absl import flags
from collections import Counter
import json
import sys 

"""
mapdata.shape is (8,)
It has ASCII codes of:
A0 A1 A2
A3  * A4
A5 A6 A7
Where "#" is wall, " " is open, "R" is ray, "F" is falcon

output.shape is (1 + 64,)
aux.shape is (64,)
OUTPUT ACTIONS:
0 : stay still
1 : move left
2 : move right
3 : move up
4 : move down
Put your action in output[0]
OUTPUT[1:] gets copied into AUX_DATA so you can use aux as memory/scratch
"""
AUX_SIZE = 64
in_shape = (8,)
out_shape = (1 + AUX_SIZE,)
aux_shape = (AUX_SIZE,)
nearby_cells_array = jnp.zeros(in_shape, dtype=jnp.int32)
aux_data = jnp.zeros(aux_shape, dtype=jnp.int32)
player = export.deserialize(sys.stdin.buffer.read())

# Maze code
WALL = True
FLOOR = False
DIRECTIONS = [
    np.array([0, 1]),  # down
    np.array([1, 0]),  # right
    np.array([0, -1]),  # up
    np.array([-1, 0]),  # left
]


def flag():
    return open("flag.txt", 'r').readlines()[0].strip()


def load_map_from_json(path="map1.json"):
  """Loads a map from a JSON file.

  Args:
    path: Path to the JSON file.

  Returns:
    A boolean numpy array, where `True` values represent walls and `False`
      represents floors (empty).
  """
  try:
    with open(path, 'r') as f:
      maze_list = json.load(f)
    maze = np.array(maze_list, dtype=bool)
    return maze
  except FileNotFoundError:
    print(f"Error: The file {path} was not found.")
    return None
  except json.JSONDecodeError:
    print(f"Error: The file {path} is not a valid JSON file.")
    return None
  except Exception as e:
    print(f"An error occurred: {e}")
    return None


def np2ascii(grid):
    viz = ""
    for row in grid:
        for cell in row:
            viz += "#" if cell else " "
        viz += "\n"
    return viz


# grid is a str repr of grid
def ascii_set(grid, row, col, val):
    width = grid.find('\n') + 1  # Include the newline character
    index = row * width + col  # Calculate the correct index
    grid_list = list(grid)  # Convert the string to a list for mutability
    grid_list[index] = val  # Set the value at the calculated index
    return "".join(grid_list)


maze = load_map_from_json("map1.json")
mapn = maze.shape[0]
maze_base_ascii = np2ascii(maze)


def cur_maze_ascii(current_falcon_positions_for_display, logged_ray_positions_list_of_lists):
    aview = maze_base_ascii
    for falcon_pos in current_falcon_positions_for_display:
        aview = ascii_set(aview, falcon_pos[0], falcon_pos[1], 'F')

    player_row, player_col = player_original_position
    aview = ascii_set(aview, player_row, player_col, 'P')

    for ray_segments in logged_ray_positions_list_of_lists:
        for ray_pos in ray_segments:
            aview = ascii_set(aview, ray_pos[0], ray_pos[1], 'R')
    return aview


def ascii_from_rowcol(aview, row, col):
    # we need aview char at row * (n + 1) + col
    return aview[row * (mapn + 1) + col]


assert maze is not None, "Maze failed to load."
assert maze.ndim == 2, "Maze must be a 2D array."
assert maze.shape[0] == maze.shape[1], "Maze must be square."
MAP_N = maze.shape[0]

player_original_position = (MAP_N//2, MAP_N//2)
aux_data = jnp.zeros(aux_shape, dtype=jnp.int32)
# aux_data starts with: [-1, 3, 4, 1, 6]
act_to_cell = [-1, 3, 4, 1, 6]


def bool2ord(cell):
    if cell:
        return ord("#")
    else:
        return ord(" ")


# Falcon Movement Routines based on initial spawn direction
FALCON_ROUTINES = {
    "spawn_west_initial_east": ["east", "up", "east", "down"],  # EUED
    "spawn_east_initial_west": ["west", "up", "west", "down"],  # WUWD
    "spawn_north_initial_down": ["down", "west", "down", "east"],  # DWDE
    "spawn_south_initial_up": ["up", "west", "up", "east"],    # UWUE
}

# ENEMY IMPLEMENTATION


def generate_falcon_start_position(maze_width, maze_height):
    """Generates a starting position and a movement routine for a falcon at a maze edge.

    Returns:
        tuple: ((row, col), routine_list) or (None, None) if invalid.
    """
    edge = np.random.randint(0, 4)  # 0: North, 1: East, 2: South, 3: West
    position = None
    routine = None

    if edge == 0:  # North
        row = 0
        col = np.random.randint(1, maze_width - 1)
        position = (row, col)
        routine = FALCON_ROUTINES["spawn_north_initial_down"]
    elif edge == 1:  # East
        row = np.random.randint(1, maze_height - 1)
        col = maze_width - 1
        position = (row, col)
        routine = FALCON_ROUTINES["spawn_east_initial_west"]
    elif edge == 2:  # South
        row = maze_height - 1
        col = np.random.randint(1, maze_width - 1)
        position = (row, col)
        routine = FALCON_ROUTINES["spawn_south_initial_up"]
    else:  # West
        row = np.random.randint(1, maze_height - 1)
        col = 0
        position = (row, col)
        routine = FALCON_ROUTINES["spawn_west_initial_east"]
    return position, routine


def move_falcon(row, col, move_command, maze_width, maze_height):
    """Moves the falcon based on a specific move command from its routine."""
    new_row, new_col = row, col
    if move_command == "west":
        new_col -= 1
    elif move_command == "up":
        new_row -= 1
    elif move_command == "east":
        new_col += 1
    elif move_command == "down":
        new_row += 1

    # Keep falcon within bounds
    new_row = max(0, min(new_row, maze_height - 1))
    new_col = max(0, min(new_col, maze_width - 1))
    return new_row, new_col


DELTA_DIRECTIONS = {
    "down": (1, 0),
    "up": (-1, 0),
    "left": (0, -1),
    "right": (0, 1)
}


def generate_ray_head_position(maze_width, maze_height):
    """Generates a single head position for a ray at an edge, and its move direction.

    Returns:
        tuple: (head_position_tuple, move_direction_str) or (None, None) if invalid.
    """
    head_pos = None
    move_direction = None
    spawn_edge = np.random.choice(["N", "E", "S", "W"])

    if maze_width <= 0 or maze_height <= 0:
        return None, None

    if spawn_edge == "N":
        move_direction = "down"
        col = np.random.randint(0, maze_width)
        head_pos = (0, col)
    elif spawn_edge == "S":
        move_direction = "up"
        col = np.random.randint(0, maze_width)
        head_pos = (maze_height - 1, col)
    elif spawn_edge == "W":
        move_direction = "right"
        row = np.random.randint(0, maze_height)
        head_pos = (row, 0)
    elif spawn_edge == "E":
        move_direction = "left"
        row = np.random.randint(0, maze_height)
        head_pos = (row, maze_width - 1)

    if head_pos is None or not (0 <= head_pos[0] < maze_height and 0 <= head_pos[1] < maze_width):
        return None, None

    return head_pos, move_direction


def move_ray_head(current_head_pos, direction, maze_width, maze_height):
    """Moves the ray's head one step in the given direction, clamping to bounds."""
    r, c = current_head_pos
    dr, dc = 0, 0

    if direction == "left":
        dc = -1
    elif direction == "right":
        dc = 1
    elif direction == "up":
        dr = -1
    elif direction == "down":
        dr = 1

    new_r, new_c = r + dr, c + dc

    final_r = max(0, min(new_r, maze_height - 1))
    final_c = max(0, min(new_c, maze_width - 1))

    return (final_r, final_c)


def get_dynamic_ray_segments(head_pos, direction_str, num_segments, maze_width, maze_height):
    """
    Calculates the positions of all ray segments based on the head's position and direction.
    Segments trail behind the head. Only returns segments that are within maze bounds.
    The list is ordered [head, segment_behind_head, segment_further_behind_head].
    """
    segments = []
    if head_pos is None:
        return segments

    move_delta_r, move_delta_c = DELTA_DIRECTIONS.get(direction_str, (0, 0))

    for i in range(num_segments):  # i = 0 for head, 1 for first tail, 2 for second tail
        seg_r = head_pos[0] - i * move_delta_r
        seg_c = head_pos[1] - i * move_delta_c

        if 0 <= seg_r < maze_height and 0 <= seg_c < maze_width:
            segments.append((seg_r, seg_c))
        # else:
            # If a segment is out of bounds, subsequent ones (further back) might also be.
            # This logic correctly adds only in-bounds segments.
    return segments


def maybe_spawn_enemy(maze_width, maze_height, spawn_prob=0.0):
    """Spawns a new enemy (falcon or ray) at a maze edge with a given probability."""
    if np.random.random() < spawn_prob:
        enemy_type = np.random.choice(["falcon", "ray"])
        if enemy_type == "falcon":
            start_pos, routine = generate_falcon_start_position(
                maze_width, maze_height)
            return "falcon", start_pos, routine  # Returns position and routine
        else:  # enemy_type == "ray"
            head_pos, direction = generate_ray_head_position(
                maze_width, maze_height)
            if head_pos and direction:
                # new_enemy_data is head_pos, new_enemy_aux_data is direction
                return "ray", head_pos, direction
    return None, None, None


# Initialize enemies
# Stores dicts: {"position": (r,c), "routine": [...], "step": 0}
active_falcons = []
initial_pos, initial_routine = generate_falcon_start_position(MAP_N, MAP_N)
if initial_pos and initial_routine:
    active_falcons.append(
        {"position": initial_pos, "routine": initial_routine, "step": 0})


managed_rays = []  # Stores dicts: {"head": (r,c), "direction": "..."}
initial_head_pos, initial_ray_direction = generate_ray_head_position(
    MAP_N, MAP_N)
if initial_head_pos and initial_ray_direction:
    managed_rays.append(
        {"head": initial_head_pos, "direction": initial_ray_direction})

game_states = []  # List to store game states at each timestep
game_trace = {}
game_trace['mapn'] = MAP_N

MAX_STEPS = 128
for i in range(MAX_STEPS):
    # Move enemies
    # Falcons
    next_active_falcons = []
    for falcon_data in active_falcons:
        current_move_idx = falcon_data["step"] % len(falcon_data["routine"])
        current_move_command = falcon_data["routine"][current_move_idx]

        new_row, new_col = move_falcon(
            falcon_data["position"][0], falcon_data["position"][1],
            current_move_command, MAP_N, MAP_N
        )
        next_active_falcons.append({
            "position": (new_row, new_col),
            "routine": falcon_data["routine"],
            "step": falcon_data["step"] + 1
        })
    active_falcons = next_active_falcons

    # Rays

    # Prepare lists for current timestep's log and next timestep's state
    all_ray_segments_for_current_log = []
    rays_for_next_timestep_state = []

    # 1. Process rays that existed at the start of this timestep
    for ray_data in managed_rays:  # These are from t-1 or earlier
        current_head = ray_data["head"]
        direction = ray_data["direction"]

        head_after_potential_move = current_head
        head_after_potential_move = move_ray_head(
            current_head, direction, MAP_N, MAP_N)

        # Removal check for existing rays based on their position after potential move
        remove_ray = False
        if direction == "down" and head_after_potential_move[0] == MAP_N - 1:
            remove_ray = True
        elif direction == "up" and head_after_potential_move[0] == 0:
            remove_ray = True
        elif direction == "right" and head_after_potential_move[1] == MAP_N - 1:
            remove_ray = True
        elif direction == "left" and head_after_potential_move[1] == 0:
            remove_ray = True

        if not remove_ray:
            rays_for_next_timestep_state.append(
                {"head": head_after_potential_move, "direction": direction})
            all_ray_segments_for_current_log.append(get_dynamic_ray_segments(
                head_after_potential_move, direction, 3, MAP_N, MAP_N))

    # 2. Possibly spawn new rays
    enemy_type, new_spawned_head_pos, new_spawned_direction = maybe_spawn_enemy(
        MAP_N, MAP_N, spawn_prob=0.1)
    if enemy_type == "falcon":  # new_enemy_data is position, new_enemy_aux_data is routine
        # new_spawned_head_pos is pos, new_spawned_direction is routine for falcon
        if new_spawned_head_pos and new_spawned_direction:
            active_falcons.append(
                {"position": new_spawned_head_pos, "routine": new_spawned_direction, "step": 0})
    elif enemy_type == "ray":
        if new_spawned_head_pos and new_spawned_direction:
            # For logging: use segments from the exact spawn position (head on edge)
            all_ray_segments_for_current_log.append(get_dynamic_ray_segments(
                new_spawned_head_pos, new_spawned_direction, 3, MAP_N, MAP_N))

            # Determine state for next timestep (includes potential first move for the new ray)
            head_for_next_ts = new_spawned_head_pos
            if i % 2 == 0:  # If rays move this timestep, the new ray also makes its first move
                head_for_next_ts = move_ray_head(
                    new_spawned_head_pos, new_spawned_direction, MAP_N, MAP_N)

            # Simple removal check for newly spawned ray (e.g. if it spawns and immediately hits opposite wall in 1-wide maze)
            # More robust removal would check head_for_next_ts against target edge. For now, assume it survives its first step if it moves.
            rays_for_next_timestep_state.append(
                {"head": head_for_next_ts, "direction": new_spawned_direction})

    # Update list of active rays for the next iteration
    managed_rays = rays_for_next_timestep_state

    # Find nearby cells of player
    player_row, player_col = player_original_position

    # Check for valid neighbors within the maze boundaries
    nearby_cells = []
    neighbors = []
    logged_ray_positions_list_of_lists = all_ray_segments_for_current_log
    current_falcon_positions_for_display = [
        f["position"] for f in active_falcons]
    cur_maze = cur_maze_ascii(current_falcon_positions_for_display, logged_ray_positions_list_of_lists)
    for i, (dr, dc) in enumerate(
        [(-1, -1), (0, -1), (1, -1), (-1, 0), (1, 0), (-1, 1), (0, 1),
         (1, 1)]):
        new_row, new_col = player_row + dc, player_col + dr
        if 0 <= new_row < len(maze) and 0 <= new_col < len(maze[0]):
            nearby_cells_array = nearby_cells_array.at[i].set(
                ord(ascii_from_rowcol(cur_maze, new_row, new_col)))
        else:
            nearby_cells_array = nearby_cells_array.at[i].set(ord("*"))

    nearby_cells_array = jnp.array(nearby_cells_array, dtype=jnp.int32)
    actions = player.call(nearby_cells_array, aux_data)
    # Update player position
    action = actions[0]  # Get the action
    # skiping actions[0] copy rest of actions into aux_data
    aux_data = actions[1:]
    row, col = player_original_position
    if action == 1:  # Left
        ncol = col - 1
        if maze[row][ncol] != WALL:
            col = ncol
    elif action == 2:  # Right
        ncol = col + 1
        if maze[row][ncol] != WALL:
            col = ncol
    elif action == 3:  # Up
        nrow = row - 1
        if maze[nrow][col] != WALL:
            row = nrow
    elif action == 4:  # Down
        nrow = row + 1
        if maze[nrow][col] != WALL:
            row = nrow

    if row < 0 or row >= MAP_N or col < 0 or col >= MAP_N:
        game_trace['flag'] = flag()
        break

    player_original_position = (row, col)

    asciiview = cur_maze_ascii(current_falcon_positions_for_display, logged_ray_positions_list_of_lists)
    player_row, player_col = player_original_position
    asciiview = ascii_set(asciiview, player_row, player_col, 'P')

    # Store the game state
    game_state = {
        "timestep": i,
        "maze": asciiview,
    }
    game_states.append(game_state)

    if maze[player_row][player_col] == WALL:
        game_trace['flag'] = "You hit a wall!"
        break

    for falcon_pos in current_falcon_positions_for_display:
        if (player_row, player_col) == falcon_pos:
            game_trace['flag'] = "Falcon got you!"
            break

    hit_by_ray = False
    for ray_segments in logged_ray_positions_list_of_lists:
        for ray_pos in ray_segments:
            if (player_row, player_col) == ray_pos:
                game_trace['flag'] = "Vaporized by Ray!"
                hit_by_ray = True
                break
        if hit_by_ray:
            break

    if hit_by_ray:
        break

else:
    game_trace['flag'] = "Ran out of time!"

game_trace['game_states'] = game_states
print(json.dumps(game_trace))

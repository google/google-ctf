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
import time


def replay_iter_func(replay):
  start_stars = replay.game.match_flags.stars()
  replay.enter_map("ruins")
  replay.teleport(1072, 3028)

  replay.enqueue(['q ', '']*80)

  yield  # Flush the keystrokes

  weapons = replay.game.projectile_system.weapons
  for i in weapons:
    if i.name.endswith("_gun"):
      assert i.y <= 1636

  # Destroy the blocks and free the NPC.
  replay.enqueue([''] * 16 + ['a'] * 39 + [''] * 2 + ['p'] * 9 + [''] * 20 + ['s'] * 6 + [''] * 4 + ['p'] * 6 + ['pa'] + ['a'] * 13 + [''] * 4 + [' '] + [''] * 4 + [' '] * 5 + [''] * 5 + [' '] * 5 + [''] * 4 + [' '] * 6 + [''] * 4 + [' '] * 5 + [''] * 5 + [' '] * 5 + [''] * 5 + [' '] * 5 + [''] * 4 + [' '] * 6 + [''] * 5 + [' '] * 7 + [''] * 18 + ['q'] * 6 + [''] * 9 + ['d'] * 35 + ['wd'] * 11 + ['d'] * 3 + [''] * 3 + [' '] * 7 + [''] * 8 + ['a'] * 11 + [''] * 38 + ['a'] * 35 + [''] * 10 + ['p'] * 6 + [''] * 24 + ['s'] * 6 + [''] * 19 + ['p'] * 7 + [''] * 4 + [' '] * 6 + [''] * 5 + [' '] * 4 + [''] * 5 + [' '] * 5 + [''] * 5 + [' '] * 5 + [''] * 4 + [' '] * 6 + [''] * 4 + [' '] * 5 + [''] * 5 + [' '] * 6 + [''] * 5 + [' '] * 6 + [''] * 5 + [' '] * 8 + [''] * 12 + ['q'] * 6 + [''] * 8 + ['p'] * 6 + [''] * 25 + ['w'] * 6 + [''] * 19 + ['s'] * 8 + [''] * 5 + [' '] * 7 + [''] + ['d'] * 27 + [''] * 11 + ['p'] * 7 + ['pd'] + ['d'] * 29 + ['da'] * 3 + ['a'] * 4 + ['a '] + [' '] * 4 + [''] * 4 + [' '] * 6 + [''] * 4 + [' '] * 5 + [''] * 5 + [' '] * 5 + [''] * 5 + [' '] * 5 + [''] * 10 + ['p'] * 7 + [''] * 11 + ['p'] * 6 + ['wp'] + ['w'] * 21 + ['w '] + [' '] * 56 + [''] * 17 + ['p'] * 7 + [''] * 16 + ['s'] * 7 + [''] * 8 + ['p'] * 6 + [''] * 19 + [' '] * 5 + [''] * 5 + [' '] * 5 + [''] * 4 + [' '] * 5 + [''] * 5 + [' '] * 5 + [''] * 4 + [' '] * 6 + [''] * 4 + [' '] * 5 + [''] * 5 + [' '] * 6 + [''] * 4 + [' '] * 5 + [''] * 5 + [' '] * 5 + [''] * 5 + [' '] * 7 + [''] * 4 + [' '] * 7 + [''] * 6 + ['p'] * 8 + [''] * 33 + ['w'] * 5 + [''] * 9 + ['p'] * 6 + [''] + [' '] * 6 + [''] * 4 + [' '] * 6 + [''] * 5 + [' '] * 5 + [''] * 5 + [' '] * 5 + [''] * 5 + [' '] * 5 + [''] * 4 + [' '] * 6 + [''] * 4 + [' '] * 5 + [''] * 5 + [' '] * 5 + [''] * 5 + [' '] * 5 + [''] * 4 + [' '] * 6 + [''] * 12 + ['a'] * 49 + [''] * 19 + ['a'] * 6 + [''] * 24 + ['w'] * 11 + [''] * 19 + ['L'] * 3 + ['aL'] * 31 + ['L'] + [''] + ['d'] * 18 + [''] * 17 + ['a'] * 7 + [''] * 23 + ['w'] * 10 + [''] * 18 + ['L'] * 7 + ['aL'] * 83 + ['a'] * 2 + ['aL'] * 17 + ['a'] * 31 + ['aL'] * 58 + ['waL'] * 6 + ['aL'] * 53 + ['L'] * 4 + ['dL'] * 8 + ['wdL'] * 9 + ['dL'] * 40 + ['wdL'] * 7 + ['dL'] * 56 + ['d'] * 27 + [''] * 15 + ['L'] * 26 + ['aL'] * 6 + ['waL'] * 12 + ['wL'] * 9 + ['L'] * 12 + ['wL'] * 4 + ['waL'] * 17 + ['aL'] * 45 + ['L'] * 2 + ['aL'] * 24 + ['L'] * 7 + ['dL'] * 6 + ['wdL'] * 43 + ['dL'] * 55 + ['L'] * 12 + ['wL'] * 37 + ['waL'] * 6 + ['aL'] * 62 + ['L'] * 6 + ['aL'] * 13 + ['a'] * 2 + [''] * 84 + ['d'] * 11 + ['wd'] * 6 + ['d'] * 22 + ['wd'] * 12 + ['w'] * 2 + ['wa'] + ['a'] * 27 + ['da'] * 2 + ['d'] * 28 + ['dL'] + ['daL'] + ['aL'] * 19 + ['a'] * 4 + [''] + ['d'] * 19 + ['wd'] * 7 + ['d'] * 83 + [''] * 10 + ['L'] * 4 + ['aL'] * 4 + ['waL'] * 17 + ['aL'] * 51 + ['a'] + [''] * 40 + ['w'] + ['wa'] * 4 + ['a'] * 9 + [''] * 10 + ['a'] * 14 + [''] * 54 + ['w'] * 7 + ['wd'] * 9 + ['d'] * 6 + [''] * 15 + ['w'] * 17 + [''] * 3 + ['d'] * 42 + [''] * 28 + ['w'] * 15 + [''] * 6 + ['w'] + ['wd'] * 2 + ['d'] * 38 + [''] * 5 + ['d'] * 13 + [''] + ['d'] * 16 + [''] * 3 + ['e'] * 4 + [''] * 4 + ['e'] * 4 + [''] * 5 + ['e'] * 4 + [''] * 64 + ['a'] * 4 + [''] * 60)
  yield
  assert replay.game.match_flags.stars() > start_stars
  replay.exit()

if __name__ == '__main__':
  replay = ReplayHelper()
  replay.start_game(replay_iter_func)

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


def replay_iter_func(replay):
  start_stars = replay.game.match_flags.stars()
  replay.enter_map("ocean")
  replay.enqueue(['']*90)
  yield
  # Grab the RangedRifle.
  replay.teleport(2159, 3077)
  replay.enqueue([' '] + [''])
  yield
  assert "Ranged" in replay.game.player.weapons[0].display_name

  # Kill 11 enemies to get the 'O' rating.
  for pos in [(801, 4432), (2177, 4328), (2433, 3889), (2273, 2962), (2209, 2833), (1921, 2048), (3200, 2048), (1216, 1105), (2015, 1105), (3665, 1105), (3665, 1105)]:
    for i in range(7):
      replay.teleport(pos[0], pos[1])
      replay.enqueue([' '] + ['']*30)
      yield

  # Talk to the grader NPC
  replay.teleport(1750, 2048)
  replay.enqueue(['']*90 + ['e'] + [''] + ['e'] + [''] + ['e'] + [''] + ['e'] + [''] + ['e'] + [''])
  yield
  assert "ORanged" in replay.game.player.weapons[0].display_name

  # Shoot the orange blocks and free the NPC.
  replay.teleport(736, 1088)
  replay.enqueue([''] * 30 + [' '] * 7 + [''] + ['a'] * 7 + ['wa'] * 11 + ['a'] * 2 + [''] + [' '] * 6 + [''] * 74 + [' '] * 7 + [''] * 19 + ['w'] * 6 + [''] * 3 + [' '] * 9 + [''] * 44 + ['a'] * 6 + ['aL'] * 43 + ['a'] * 2 + [''] + [' '] * 3 + [''] * 6 + [' '] * 5 + [''] * 5 + [' '] * 4 + [''] * 5 + [' '] * 6 + [''] * 17 + [' '] * 7 + [''] * 12 + ['a'] * 7 + ['aL'] * 54 + ['a'] + [''] * 10 + ['d'] * 7 + ['dL'] * 18 + ['wdL'] * 11 + ['dL'] + ['d'] * 14 + ['dL'] * 42 + ['wdL'] * 9 + ['wd'] + ['d'] * 7 + ['dL'] * 83 + ['wdL'] * 6 + ['wd'] * 4 + ['d'] * 5 + ['dL'] * 54 + ['wdL'] * 6 + ['wd'] + ['d'] * 12 + ['dL'] * 30 + ['wdL'] * 3 + ['wd'] * 4 + ['d'] * 31 + ['dL'] * 24 + ['d'] * 68 + ['dL'] * 62 + ['L'] + [''] * 2 + ['e'] * 5 + [''] * 4 + ['e'] * 5 + [''] * 6 + ['e'] * 5 + [''] * 5 + ['e'] * 4 + [''] * 48)
  yield

  assert replay.game.match_flags.stars() > start_stars

  # Test completed
  replay.exit()


if __name__ == '__main__':
  replay = ReplayHelper()
  replay.start_game(replay_iter_func)

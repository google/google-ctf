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
  replay.enqueue([''] * 60)
  yield
  replay.enqueue(['d'] * 60)
  yield  # Flush the keystrokes
  enemy_count = len([o for o in replay.game.objects if o.nametype == "Enemy" and not o.dead])

  # Game state assertions
  assert not replay.game.player.dead

  # glitch

  replay.enqueue(['s', ' '] * 120)

  yield  # Flush the keystrokes

  # Game state assertions
  assert not replay.game.player.dead
  new_enemy_count = len([o for o in replay.game.objects if o.nametype == "Enemy" and not o.dead])
  assert new_enemy_count < enemy_count

  # Walk to the NPC.
  replay.enqueue([''] * 200 + ['L'] * 3 + ['dL'] * 110 + ['wdL'] * 5 + ['wd'] * 3 + ['d'] * 47 + ['dL'] * 11 + ['wdL'] * 8 + ['dL'] * 20 + ['wdL'] * 7 + ['dL'] * 10 + ['d'] * 62 + ['dL'] * 29 + ['d'] * 21 + ['dL'] * 123 + ['d'] * 82 + ['dL'] * 22 + ['wdL'] * 7 + ['dL'] * 5 + ['d'] * 48 + ['dL'] * 25 + ['wdL'] * 6 + ['dL'] * 11 + ['d'] * 31 + ['dL'] * 46 + ['wdL'] * 8 + ['dL'] * 5 + ['d'] * 18 + ['dL'] * 45 + ['wdL'] * 7 + ['dL'] * 12 + ['d'] * 21 + ['dL'] * 29 + ['wdL'] * 3 + ['wd'] + ['w'] * 2 + [''] * 5 + ['w'] * 5 + [''] * 5 + ['w'] * 5 + [''] * 3 + ['w'] * 8 + ['wd'] * 4 + ['d'] * 6 + ['wd'] * 3 + ['w'] * 6 + [''] * 3 + ['w'] * 6 + [''] * 4 + ['w'] * 6 + [''] * 4 + ['w'] * 8 + ['wd'] * 4 + ['d'] * 4 + ['wd'] * 5 + ['w'] * 5 + [''] * 2 + ['w'] * 7 + [''] * 3 + ['w'] * 7 + ['wd'] * 3 + ['d'] * 5 + ['wd'] * 2 + ['w'] * 5 + [''] * 4 + ['w'] * 6 + [''] * 3 + ['w'] * 7 + ['wd'] * 3 + ['d'] * 5 + ['wd'] * 6 + ['d'] * 4 + ['wd'] * 5 + ['w'] * 4 + [''] * 3 + ['w'] * 5 + [''] * 4 + ['w'] * 6 + [''] * 5 + ['w'] * 5 + [''] * 5 + ['w'] * 5 + [''] * 4 + ['w'] * 5 + [''] * 4 + ['w'] * 6 + [''] * 5 + ['w'] * 5 + [''] * 6 + ['w'] * 5 + [''] * 5 + ['w'] * 6 + ['wd'] * 3 + ['d'] * 6 + ['wd'] * 6 + ['d'] * 6 + ['wd'] * 6 + ['d'] * 6 + ['wd'] * 6 + ['d'] * 7 + ['wd'] * 7 + ['d'] * 6 + ['wd'] * 4 + ['w'] * 5 + [''] * 5 + ['w'] * 6 + [''] * 5 + ['w'] * 6 + [''] * 6 + ['w'] * 5 + [''] * 5 + ['w'] * 10 + [''] * 4 + ['w'] * 11 + ['wd'] * 5 + ['w'] * 4 + ['wd'] * 5 + ['d'] * 8 + ['wd'] * 4 + ['w'] * 10 + ['wd'] * 5 + ['d'] * 6 + ['wd'] * 8 + ['d'] * 6 + ['wd'] * 6 + ['d'] * 35 + ['dL'] * 39 + ['wdL'] * 5 + ['dL'] * 8 + ['wdL'] * 6 + ['dL'] * 5 + ['d'] * 27 + [''] * 9 + ['e'] * 3 + [''] * 4 + ['e'] * 5 + [''] * 4 + ['e'] * 5 + [''] * 5 + ['e'] * 4 + [''] * 42 + ['d'] * 33 + [''])
  yield
  assert replay.game.match_flags.stars() > start_stars
  replay.exit()


if __name__ == '__main__':
  replay = ReplayHelper()
  replay.start_game(replay_iter_func)

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
  replay.enter_map("beach")
  replay.teleport(2531, 900)

  replay.enqueue([''] * 85 + ['d'] * 2 + ['dL'] * 20 + ['wdL'] + ['dL'] * 31 + ['wdL'] + ['dL'] * 31 + ['wdL'] + ['dL'] * 110 + ['wdL'] + ['dL'] * 35 + ['d'] * 32 + [''] * 21 + ['a'] * 7 + [''] * 34 + ['d'] * 6 + [''] * 72 + ['w'] + [''] * 2 + ['d'] * 48 + ['dL'] * 11 + ['L'] * 18 + ['dL'] + ['d'] * 21 + [''] * 71 + ['w'] + [''] + ['a'] * 22 + [''] * 82 + [' '] * 5 + ['w '] + ['L '] * 3 + ['dL '] * 101 + ['dL'] * 9 + ['d'] * 16 + [''] * 14 + ['w'] + [''] * 76 + ['a'] * 41 + ['wa'] + ['a'] * 6 + [''] * 27 + ['d'] * 4 + [''] * 76 + [' '] * 4 + [''] * 2 + ['w'] + [''] * 106 + [' '] * 6 + [''] * 6 + ['w'] + [''] * 114 + [' '] * 3 + ['w '] + [' '] + [''] * 112 + [' '] * 5 + [''] + ['w'] + [''] * 111 + [' '] * 5 + [''] * 5 + ['w'] + [''] * 111 + [' '] * 6 + [''] + ['w'] + [''] * 70 + ['L'] * 16 + ['dL'] * 39 + ['wdL'] + ['dL'] * 2 + ['d'] * 3 + ['wd'] + ['d'] * 5 + ['wd'] + ['d'] * 5 + ['wd'] + ['d'] * 5 + ['wd'] + ['d'] * 5 + ['wd'] + ['d'] * 5 + ['wd'] + ['d'] * 5 + ['wd'] + ['d'] * 5 + ['wd'] + ['d'] * 5 + ['wd'] + ['d'] * 5 + ['wd'] + ['d'] * 5 + ['wd'] + ['d'] * 5 + ['wd'] + ['d'] * 5 + ['wd'] + ['d'] * 5 + ['wd'] + ['d'] * 13 + [''] * 4 + ['e'] * 4 + [''] * 4 + ['e'] * 4 + [''] * 5 + ['e'] * 4 + [''] * 26 + ['e'] * 4 + [''] * 7 + ['e'] * 3 + [''] * 50 + ['d'] * 12 + ['dL'] * 38 + ['d'] + ['da'] + ['a'] * 6 + [''] * 9)

  yield
  assert replay.game.match_flags.stars() > start_stars
  replay.exit()


if __name__ == '__main__':
  replay = ReplayHelper()
  replay.start_game(replay_iter_func)

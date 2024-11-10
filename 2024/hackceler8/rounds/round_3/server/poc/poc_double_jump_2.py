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
  replay.enter_map("cloud")

  replay.enqueue([''] * 63 + ['a'] * 43 + ['wa'] * 5 + ['a'] * 51 + ['wa'] + ['a'] * 37 + [''] * 18 + ['w'] + [''] * 45 + ['a'] * 10 + ['wa'] + ['a'] * 55 + ['wa'] + ['a'] * 55 + ['wa'] + ['a'] * 90 + [''] * 7 + ['d'] * 12 + ['dL'] * 5 + ['wdL'] * 9 + ['dL'] * 50 + ['d'] * 45 + ['wd'] * 3 + ['w'] * 4 + ['wa'] * 18 + ['waL'] * 2 + ['aL'] * 28 + ['daL'] + ['dL'] + ['d'] * 16 + [''] * 18 + ['d'] * 6 + [''] * 75 + ['L'] * 2 + ['aL'] + ['waL'] * 117 + ['aL'] * 2 + ['a'] * 31 + ['aL'] * 20 + ['waL'] * 6 + ['aL'] * 64 + ['a'] * 36 + ['da'] + ['d'] * 15 + ['dL'] * 14 + ['wdL'] * 115 + ['dL'] * 6 + ['d'] * 21 + [''] * 14 + ['a'] * 8 + ['aL'] * 22 + ['waL'] * 7 + ['aL'] * 48 + ['a'] * 7 + ['aL'] * 19 + ['a'] * 76 + ['da'] * 3 + ['d'] * 20 + ['dL'] * 19 + ['d'] * 2 + [''] * 7 + ['a'] * 7 + ['aL'] * 14 + ['a'] * 2 + [''] * 14 + ['a'] * 7 + [''] * 11 + ['d'] * 71 + ['dL'] * 2 + ['wdL'] * 121 + ['dL'] * 8 + ['d'] * 8 + [''] * 8 + ['a'] * 4 + ['wa'] * 14 + ['a'] * 58 + [''] * 108 + ['L'] * 16 + ['dL'] * 11 + ['wdL'] * 32 + ['dL'] * 23 + ['d'] * 77 + [''] * 51 + ['w'] * 7 + ['wd'] * 30 + ['wdL'] * 2 + ['dL'] * 33 + ['d'] * 50 + [''] * 2 + ['a'] * 13 + ['aL'] * 6 + ['waL'] * 10 + ['aL'] * 101 + ['waL'] + ['aL'] * 79 + ['a'] * 151 + [''] * 6 + ['d'] * 30 + [''] * 21 + ['w'] * 3 + ['wa'] * 7 + ['a'] * 93 + [''] * 41 + ['a'] * 13 + [''] * 65 + ['a'] * 18 + ['aL'] * 12 + ['waL'] * 15 + ['aL'] * 191 + ['a'] * 29 + ['da'] + ['d'] * 39 + [''] * 19 + ['d'] * 8 + [''] * 20 + ['e'] * 4 + [''] * 4 + ['e'] * 4 + [''] * 4 + ['e'] * 4 + [''] * 77)
  yield

  # Check that an NPC got freed.
  assert replay.game.match_flags.stars() > start_stars

  replay.exit()


if __name__ == '__main__':
  replay = ReplayHelper()
  replay.start_game(replay_iter_func)

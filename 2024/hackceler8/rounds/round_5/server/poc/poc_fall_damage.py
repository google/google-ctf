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
from time import sleep



def replay_iter_func(replay):
  start_stars = replay.game.match_flags.stars()
  replay.enter_map("ruins")
  replay.enqueue([''] * 112 + [' '] * 48 + ['a '] * 30 + ['a'] * 10 + ['aL'] * 31 + ['waL'] * 36 + ['wa'] * 2 + ['a'] * 43 + ['a '] + ['a'] * 2 + ['da'] * 3 + ['d'] * 45 + [''] * 43 + [''] * 5 + ['d'] * 8 + [''] * 11 + ['d'] * 11 + [''] * 4 + ['a'] * 72 + [''] * 6 + [' '] * 38 + ['a '] * 50 + [' '] * 103 + [''] + ['a'] + ['a '] * 99 + [' '] * 115 + ['a '] * 38 + [' '] * 52 + [''] * 19 + ['d'] * 58 + ['da'] * 3 + ['a'] * 13 + [''] * 32 + ['w'] * 10 + ['wd'] * 3 + ['wdL'] * 2 + ['dL'] * 53 + ['d'] * 49 + [''] + ['p'] * 4 + [''] * 14 + ['s'] * 3 + [''] * 3 + ['p'] * 5 + ['d'] * 7 + ['dL'] * 66 + ['dL '] * 14 + ['L '] + [' '] * 126 + [''] * 52 + ['e'] * 3 + [''] * 3 + ['e'] * 2 + [''] * 3 + ['e'] * 2 + [''] * 3 + ['e'] * 2 + [''] * 3 + ['e'] * 2 + [''] * 2 + ['e'] * 3 + [''] * 2 + ['e'] * 2 + [''] * 3 + ['e'] * 3 + [''] * 57)
  yield
  assert replay.game.match_flags.stars() > start_stars
  replay.exit()

if __name__ == '__main__':
  replay = ReplayHelper()
  replay.start_game(replay_iter_func)

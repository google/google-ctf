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
  replay.enter_map('ruins')
  replay.enqueue([''] * 112 + [' '] * 10 + [''] * 4 + ['a'] * 44 + [''] * 15 + ['w'] * 6 + ['wa'] * 33 + [''] * 21 + ['w'] * 5 + ['wa'] * 42 + ['w'] * 21 + ['wa'] * 9 + ['a'] * 75 + [''] * 108 + ['d'] * 74 + [''] * 20 + ['d'] * 19 + [''] * 16 + ['d'] * 7 + [''] * 27 + ['a'] * 6 + [''] * 80 + ['a'] * 16 + [''] * 8 + [' '] + [''] * 16 + [' '] * 11 + [''] * 13 + [' '] * 9 + [''] * 12 + [' '] * 10 + [''] * 13 + [' '] * 9 + [''] * 5 + [' '] * 8 + [''] * 5 + [' '] * 8 + [''] * 6 + [' '] * 7 + [''] * 7 + [' '] * 9 + [''] * 4 + [' '] * 8 + [''] * 4 + [' '] * 2 + ['d '] * 3 + ['d'] * 17 + [''] * 26 + ['a'] * 15 + [''] * 8 + [' '] * 9 + [''] * 14 + [' '] * 8 + [''] + ['a'] * 6 + [''] * 12 + [' '] * 8 + [''] * 13 + ['d'] * 20 + [''] * 118 + ['a'] * 7 + ['wa'] * 13 + ['a'] * 44 + [''] * 9 + ['a'] * 23 + [''] * 24 + [' '] * 6 + [''] + ['d'] * 43 + [''] * 16 + ['d'] * 12 + [''] * 15 + ['d'] * 30 + [''] * 28 + ['a'] * 97 + [''] * 97 + ['w'] * 74 + [''] * 39 + ['w'] * 17 + [''] * 23 + ['d'] * 9 + [''] * 23 + ['d'] * 13 + [''] * 9 + ['d'] * 34 + [''] * 4 + [' '] * 10 + ['d'] * 17 + ['d '] * 12 + ['d'] * 11 + ['d '] * 10 + ['d'] * 8 + ['d '] + [' '] * 6 + [''] * 3 + ['a'] * 3 + ['a '] * 8 + ['a'] * 5 + ['a '] * 5 + [' '] * 2 + ['d'] * 14 + [''] + [' '] * 8 + [''] * 6 + [' '] * 8 + [''] * 7 + [' '] * 7 + [''] * 5 + [' '] * 6 + ['a '] + ['a'] * 53 + [''] + ['d'] * 4 + [''] * 3 + [' '] * 7 + [''] * 7 + [' '] * 6 + ['a '] + ['a'] * 3 + ['a '] * 7 + ['a'] * 37 + ['da'] * 2 + ['d'] * 5 + [''] + [' '] * 5 + [''] * 5 + [' '] * 6 + [''] * 5 + [' '] * 7 + [''] * 5 + [' '] * 7 + [''] * 12 + ['d'] * 22 + [''] * 14 + ['a'] * 37 + ['a '] + [' '] * 7 + [''] * 5 + [' '] * 6 + [''] * 5 + [' '] * 6 + [''] * 6 + [' '] * 9 + [''] * 6 + [' '] * 9 + [''] * 7 + [' '] * 10 + [''] * 6 + [' '] * 9 + [''] * 10 + [' '] * 9 + [''] * 50)
  yield
  replay.enqueue(['q'])
  for i in range(50):
    replay.enqueue(['q ', '', ' '])
  yield
  replay.enqueue([''] * 10 + ['a'] * 42)
  yield
  for i in range(50):
    replay.enqueue(['q ', '', ' '])
  yield
  replay.enqueue([''] * 4 + ['a'] * 54)
  yield
  for i in range(50):
    replay.enqueue(['q ', '', ' '])
  yield
  replay.enqueue([''] * 60 + ['w'] * 6 + ['wa'] * 6 + ['a'] * 38 + [''] * 14 + ['a'] * 38 + [''] * 5 + ['a'] * 211 + ['wa'] * 27 + ['a'] * 49 + [''] * 3 + [' '] * 7 + ['d '] + ['d'] * 19 + [''] * 19 + ['a'] * 27 + [''] * 6 + [' '] * 8 + [''] * 2 + ['d'] * 13 + [''] * 4 + ['p'] * 7 + [''] * 25 + ['s'] * 5 + [''] * 4 + ['s'] * 4 + [''] * 22 + ['p'] * 8 + [''] * 48 + ['d'] * 7 + ['wd'] * 2 + ['w'] * 7 + [''] * 9 + ['d'] * 39 + [''] * 5 + ['d'] * 27 + [''] * 6 + ['w'] * 13 + [''] * 12 + ['w'] * 13 + [''] * 3 + [' '] * 8 + [''] * 12 + [' '] * 9 + [''] * 16 + ['w'] * 12 + [''] * 7 + [' '] * 7 + [''] * 9 + [' '] * 9 + [''] * 8 + [' '] * 7 + [''] * 5 + ['w'] * 11 + [''] * 4 + [' '] * 8 + [''] * 5 + [' '] * 9 + [''] * 6 + [' '] * 8 + [''] * 6 + [' '] * 7 + [''] * 18 + ['d'] * 12 + ['wd'] * 12 + ['d'] * 15 + ['sd'] * 5 + ['s'] * 6 + ['sda'] + ['sd'] * 5 + ['d'] * 3 + [''] * 56 + ['w'] * 5 + ['wa'] * 13 + ['a'] * 35 + [''] * 18 + ['a'] * 5 + [''] * 22 + ['w'] * 6 + ['wa'] * 3 + ['a'] * 5 + [''] * 10 + ['a'] * 6 + [''] * 7 + ['a'] * 4 + [''] * 8 + ['a'] * 5 + [''] * 5 + ['a'] * 8 + [''] * 20 + ['w'] * 8 + [''] * 6 + ['d'] * 26 + [''] * 13 + ['d'] * 9 + [''] * 36 + ['w'] * 8 + ['wd'] * 5 + ['d'] * 53 + [''] * 4 + ['s'] * 11 + [''] * 8 + ['e'] * 7 + [''] + ['e'] + [''] + ['e'] + [''] + ['e'] + [''] * 90)
  yield
  end_stars = replay.game.match_flags.stars()
  assert (end_stars - start_stars) > 0

if __name__ == '__main__':
  replay = ReplayHelper()
  replay.start_game(replay_iter_func)

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
  # Enter the ocean level and exit soon after.
  replay.enter_map("ocean")
  replay.enqueue(['']*90 + ['E'] + ['']*90)
  yield

  # Enter the ruins level and use the water env effect to swim to the NPC.
  replay.enter_map("ruins")
  replay.enqueue([''] * 211 + ['a'] * 29 + ['aL'] * 24 + ['waL'] * 8 + ['aL'] * 35 + ['waL'] * 7 + ['aL'] * 39 + ['waL'] * 10 + ['aL'] * 62 + ['L'] + [''] * 17 + ['d'] * 31 + [''] * 35 + ['a'] * 92 + [''] * 21 + [' '] * 3 + ['d '] * 5 + ['d'] * 4 + ['d '] * 55 + [' '] * 34 + ['a '] * 9 + [' '] * 32 + ['d '] * 21 + [' '] * 38 + ['a '] * 9 + [' '] * 14 + ['a '] * 10 + [' '] * 4 + ['a '] * 22 + ['wa '] * 8 + ['a '] * 11 + [' '] * 123 + ['a '] * 17 + [' '] * 7 + ['a '] * 21 + ['a'] * 2 + ['a '] * 147 + [' '] * 18 + ['a '] * 4 + [' '] * 32 + [''] * 36 + ['w'] * 6 + [''] * 36 + ['a'] * 13 + ['aL'] * 62 + ['a'] * 47 + ['wa'] * 6 + ['a'] * 7 + ['wa'] * 6 + ['a'] * 7 + ['wa'] * 7 + ['a'] * 9 + ['wa'] * 8 + ['a'] * 7 + ['wa'] * 8 + ['a'] * 5 + ['wa'] * 6 + ['a'] * 7 + ['wa'] * 6 + ['a'] * 6 + ['wa'] * 5 + ['a'] * 6 + ['wa'] * 6 + ['a'] * 9 + ['wa'] * 10 + ['a'] * 6 + ['wa'] * 7 + ['a'] * 5 + ['wa'] * 14 + ['wda'] * 5 + ['da'] * 2 + ['d'] * 4 + ['wd'] * 8 + ['d'] * 6 + ['wd'] * 9 + ['d'] * 5 + ['wd'] * 6 + ['w'] + ['wa'] * 2 + ['a'] * 47 + ['aL'] * 60 + ['a'] * 10 + [''] * 12 + ['w'] * 6 + [''] * 12 + ['a'] * 10 + ['ea'] * 4 + ['e'] * 2 + [''] * 6 + ['e'] * 6 + [''] * 12 + ['e'] * 4 + [''] * 58 + ['a'] * 22 + [''] * 5 + ['d'] * 4 + [''] * 77)
  yield

  assert replay.game.match_flags.stars() > start_stars

  # Test completed
  replay.exit()


if __name__ == '__main__':
  replay = ReplayHelper()
  replay.start_game(replay_iter_func)

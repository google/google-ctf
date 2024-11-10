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
  replay.enqueue([''] * 146 + ['a'] * 13 + ['aL'] * 23 + ['waL'] * 8 + ['aL'] * 30 + ['L'] + [''] * 67 + ['d'] * 15 + [''] * 4 + ['d'] * 30 + [''] * 9 + ['a'] * 9 + ['wa'] * 7 + ['a'] * 25 + ['wa'] * 6 + ['a'] * 13 + ['aL'] * 42 + ['a'] * 9 + [''] * 53 + ['d'] * 5 + ['dL'] * 53 + ['wdL'] * 12 + ['dL'] * 13 + ['L'] + [''] * 10 + ['d'] * 10 + [''] * 4 + ['e'] * 4 + [''] * 4 + ['e'] * 5 + [''] * 4 + ['e'] * 5 + [''] * 14 + ['e'] * 5 + [''] * 5 + ['e'] * 4 + [''] * 30 + ['L'] * 31 + ['dL'] * 29 + ['d'] + ['da'] + ['a'] * 5 + [''] * 30)

  yield  # Flush the keystrokes

  # Game state assertions
  assert not replay.game.player.dead

  # Check that an NPC got freed.
  assert replay.game.match_flags.stars() > start_stars

  # Test completed
  replay.exit()


if __name__ == '__main__':
  replay = ReplayHelper()
  replay.start_game(replay_iter_func)

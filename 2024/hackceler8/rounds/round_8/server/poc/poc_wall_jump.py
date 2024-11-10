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
  replay.enter_map("ruins")
  replay.teleport(256, 3169)
  replay.enqueue([''] * 85 + ['d'] * 24 + ['dL'] * 7 + ['wdL'] + ['dL'] * 41 + ['wdL'] + ['dL'] * 5 + ['wdL'] + ['dL'] * 22 + ['d'] * 7 + ['a'] * 8 + [''] * 73 + ['a'] * 9 + ['aL'] * 12 + ['waL'] + ['aL'] * 41 + ['waL'] + ['aL'] * 5 + ['waL'] + ['aL'] * 22 + [''] * 2 + ['d'] * 23 + [''] * 16 + ['d'] * 3 + [''] * 47 + ['L'] * 2 + ['dL'] * 2 + ['wdL'] + ['dL'] * 41 + ['wdL'] + ['dL'] * 5 + ['wdL'] + ['dL'] * 5 + ['wdL'] + ['dL'] * 13 + ['d'] * 14 + [''] * 81 + ['e'] * 3 + [''] * 5 + ['e'] * 3 + [''] * 5 + ['e'] * 5 + [''] * 68 + ['d'] * 6)
  yield
  # Check that the NPC got freed.
  assert replay.game.match_flags.stars() > start_stars
  replay.exit()


if __name__ == '__main__':
  replay = ReplayHelper()
  replay.start_game(replay_iter_func)

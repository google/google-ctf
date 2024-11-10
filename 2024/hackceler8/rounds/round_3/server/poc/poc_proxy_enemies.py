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
  # Pick up weapon
  replay.teleport(1184, 3008)
  replay.enqueue(['']*90 + [' '] + [''])
  yield

  # Shoot the ghost hitboxes.
  replay.teleport(881, 3634)
  replay.enqueue(['a'])
  for i in range(120):
    replay.enqueue([' '] + ['']*30)
  yield
  for o in replay.game.objects:
    if o.nametype == "Enemy" and not o.dead:
      assert "ghost" not in o.name

  # Walk to the NPC and free it.
  replay.teleport(769, 3314)
  replay.enqueue([''] * 270 + ['a'] * 3 + ['aL'] * 50 + ['waL'] * 9 + ['aL'] * 76 + ['a'] + [''] * 28 + ['w'] * 14 + [''] * 8 + ['a'] * 24 + [''] * 35 + ['w'] + ['wd'] * 8 + ['d'] * 21 + ['dL'] * 15 + ['wdL'] * 11 + ['dL'] * 32 + ['d'] * 20 + [''] * 48 + ['w'] * 6 + [''] * 16 + ['a'] * 4 + ['aL'] * 51 + ['a'] * 3 + [''] * 15 + ['L'] + ['aL'] * 2 + ['waL'] * 9 + ['aL'] * 24 + ['a'] + [''] * 2 + ['w'] * 4 + ['wd'] * 10 + ['d'] * 25 + ['wd'] * 11 + ['d'] * 106 + [''] * 4 + ['e'] * 4 + [''] * 4 + ['e'] * 4 + [''] * 5 + ['e'] * 3 + [''] * 89 + ['d'] * 37 + ['da'] * 2 + ['a'] * 4 + [''] * 23)
  yield
  assert replay.game.match_flags.stars() > start_stars
  replay.exit()


if __name__ == '__main__':
  replay = ReplayHelper()
  replay.start_game(replay_iter_func)

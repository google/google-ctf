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
  # Pick up weapon.
  replay.teleport(1232, 816)
  replay.enqueue([''] * 90 + [' '] * 1 + [''])
  yield
  # Check we have the limited weapon.
  assert len(replay.game.player.weapons) > 0
  assert replay.game.player.weapons[0].usage_limit == 3

  # Go to where the enemy is guarding the NPC, kill it using the max usage bypass and free the NPC.
  replay.teleport(5030, 737)
  replay.enqueue(['a'] * 15 + [''] * 5 + ['d'] * 4 + [''] * 46 + [' '] * 5 + [''] * 10 + ['w'] * 8 + [''] * 104 + [' '] * 5 + [''] * 3 + ['w'] * 9 + [''] * 107 + ['q'] * 4 + ['wq'] + ['w'] * 10 + [''] * 98 + [' '] * 5 + [''] * 3 + ['w '] * 3 + [' '] + [''] * 3 + ['w'] * 6 + [''] * 97 + [' '] * 4 + [''] * 2 + ['w'] * 6 + [''] * 105 + [' '] * 5 + [''] + ['w'] * 9 + [''] * 103 + ['L'] * 6 + ['Ld'] * 86 + ['d'] + [''] * 4 + ['e'] * 3 + [''] * 5 + ['e'] * 4 + [''] * 9 + ['e'] * 6 + [''] * 50 + ['d'] * 32 + ['da'] * 2 + ['a'] * 4 + [''] * 36)
  yield

  # Check that an NPC got freed.
  assert replay.game.match_flags.stars() > start_stars

  replay.exit()


if __name__ == '__main__':
  replay = ReplayHelper()
  replay.start_game(replay_iter_func)

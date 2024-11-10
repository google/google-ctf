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
from game.components.weapon.weapon import Weapon


def replay_iter_func(replay):
  start_stars = replay.game.match_flags.stars()
  # Get the cannon from the ruins map to set the global damage.
  replay.enter_map("ruins")
  replay.teleport(1216, 2688)
  replay.enqueue(['']*90 + [' '] + [''])
  yield

  # Enter the cloud map and get the weapon.
  replay.enter_map("cloud")
  replay.teleport(2320, 3168)
  replay.enqueue(['']*90 + [' '] + [''])
  yield

  # Check we have the weapon and it has the cannon's damage.
  found = False
  for w in replay.game.player.weapons:
    if w.name == "slow_gun" and w.equipped:
      found = True
  assert found
  assert Weapon.damage >= 100

  # Use the gun to defeat the enemy guarding the NPC and free the NPC.
  replay.teleport(1152, 1857)
  replay.enqueue([''] * 130 + ['a'] * 6 + ['La'] * 4 + ['Lwa'] * 22 + ['wa'] * 7 + ['a'] * 20 + [''] * 11 + ['a'] * 5 + [''] * 8 + ['a'] + [''] * 129 + ['a'] * 14 + [''] + [' '] * 5 + [''] * 16 + ['a'] * 26 + ['La'] * 36 + ['a'] * 29 + [''] * 16 + ['a'] * 7 + [''] * 5 + ['e'] * 4 + [''] * 7 + ['e'] * 3 + [''] * 14 + ['e'] * 5 + [''] * 55 + ['d'] * 13 + [''] * 28)
  yield

  assert replay.game.match_flags.stars() > start_stars
  replay.exit()


if __name__ == '__main__':
  replay = ReplayHelper()
  replay.start_game(replay_iter_func)

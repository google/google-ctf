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
  replay.enter_map("ocean")
  replay.enqueue([''] * 90)
  yield
  # Pick up weapons.
  replay.teleport(2160, 4048)
  replay.enqueue([' '] + [''])
  yield
  replay.teleport(2160, 3712)
  replay.enqueue([' '] + [''])
  yield
  replay.teleport(2640, 3552)
  replay.enqueue([' '] + [''])
  yield
  replay.teleport(2640, 3248)
  replay.enqueue([' '] + [''])
  yield
  replay.teleport(2160, 3104)
  replay.enqueue([' '] + [''])
  yield
  # Check we have all weapons.
  assert len(replay.game.player.weapons) >= 5
  # Go to where the enemy is guarding the NPC.
  replay.teleport(4321, 2016)
  replay.enqueue(['']*70)
  yield
  replay.enqueue(['d'] * 11)
  # Kill enemy using the rapid fire glitch.
  for i in range(5):
    replay.enqueue([' '] + ['q'] + [' '] + [''] + [' '])

  # Free the NPC.
  replay.enqueue(['ld']*600 + ['e'] + [''] + ['e'] + [''] + ['e'] + ['']*120)
  yield
  # Check that an NPC got freed.
  assert replay.game.match_flags.stars() > start_stars
  replay.exit()
if __name__ == '__main__':
  replay = ReplayHelper()
  replay.start_game(replay_iter_func)

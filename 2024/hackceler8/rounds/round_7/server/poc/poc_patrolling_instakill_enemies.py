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

# Ugly :/
mapping = {
  "Keys.RIGHT": "",
  "Keys.LSHIFT": "L",
  "Keys.A": "a",
  "Keys.S": "s",
  "Keys.D": "d",
  "Keys.W": "w",
  "Keys.E": "e",
}

def replay_iter_func(replay):
  start_stars = replay.game.match_flags.stars()
  replay.enter_map("ocean")

  yield  # Flush the keystrokes

  # Wait for level transition
  replay.enqueue([''] * 70)
  yield

  with open('poc/challenge_patrolling_instakill_enemies_replay.txt', 'r') as f:
    contents = f.read().split('\n')

  for line in contents:
    for k, v in mapping.items():
      line = line.replace(k, v)
    line = line.replace(",", "")
    print(line)
    replay.enqueue([line])
    yield
  # Game state assertions
  assert not replay.game.player.dead

  # Skip dialog
  replay.enqueue(['e', ''] * 60)
  yield

  assert replay.game.match_flags.stars() > start_stars

  # Test completed
  replay.exit()


if __name__ == '__main__':
  replay = ReplayHelper()
  replay.start_game(replay_iter_func)

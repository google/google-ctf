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

# PoC for the save interrupt challenge, part 1.
# Run this while connecting to the server, then run part 2.

from poc.helper import ReplayHelper

def key_obtained(game):
  for i in game.items:
    if i.name == "key":
      return True
  return False

def replay_iter_func(replay):
  replay.enter_map("ruins")
  # Teleport to portal that leads to the key and grab the key.
  replay.teleport(1242, 3633)
  replay.enqueue([''] * 95 + ['d'] * 5 + ['wd'] * 34 + ['d'] * 36 + ['wd'] * 4 + ['d'] * 4 + [''] * 26 + ['w'] * 6 + ['wa'] * 6 + ['a'] * 4 + [''] * 80)
  yield
  assert key_obtained(replay.game)

  # Teleport in front of the the key-gate, insert key, then remove and disconnect right before the gate state is saved.
  replay.teleport(1242, 3633)
  replay.enqueue(['d'] * 5 + [''] * 6 + ['e'] * 6 + [''] * 7 + ['d'] * 9 + [''] * 21 + ['e'])
  yield

  # Check that we still have the key.
  assert key_obtained(replay.game)
  exit(0)


if __name__ == '__main__':
  replay = ReplayHelper()
  replay.start_game(replay_iter_func)

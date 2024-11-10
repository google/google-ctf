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

# PoC for the save interrupt challenge, part 2.
# Run this while connecting to the server after having run part 1.

from poc.helper import ReplayHelper


def replay_iter_func(replay):
  start_stars = replay.game.match_flags.stars()
  # Check that we have the key at the start.
  key_obtained = False
  for i in replay.game.items:
      if i.name == "key":
          key_obtained = True
          break
  assert key_obtained

  # Teleport in front of the the key-gate
  replay.enter_map("ruins")
  replay.teleport(1242, 3633)
  # First gate should already be open. Insert key into second gate.
  replay.enqueue([''] * 85 + ['d'] * 54 + [''] * 4 + ['e'] * 5 + [''] * 8 + ['d'] * 36 + [''] * 5 + ['e'] * 4 + [''] * 5 + ['e'] * 5 + [''] * 17 + ['e'] * 4 + [''] * 20 + ['e'] * 4 + [''] * 14 + ['e'] * 4 + [''] * 52 + ['L'] * 6 + ['dL'] * 35 + ['d'] + ['da'] + ['a'] * 7 + ['']*60)
  yield

  # Check that an NPC got freed.
  assert replay.game.match_flags.stars() > start_stars

  replay.exit()


if __name__ == '__main__':
  replay = ReplayHelper()
  replay.start_game(replay_iter_func)

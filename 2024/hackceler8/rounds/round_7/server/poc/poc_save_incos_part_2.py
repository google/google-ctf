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

# PoC for the save inconsistency challenge, part 2.
# Run this while connecting to the server after having run part 1.

from poc.helper import ReplayHelper


def replay_iter_func(replay):
  start_stars = replay.game.match_flags.stars()

  replay.enqueue([''] * 9 + ['L'] * 7 + ['Ld'] * 89 + ['Lda'] * 2 + ['La'] * 190)
  yield

  # Check that got have the key.
  key_obtained = False
  for i in replay.game.items:
      if i.name == "key":
          key_obtained = True
          break
  assert key_obtained

  # Move to place in ruins map where the key-gate is.
  replay.enter_map("ruins")
  replay.teleport(1242, 3633)
  # Open gate and free NPC.
  replay.enqueue([''] * 90 + ['e'] * 7 + [''] * 5 + ['d'] * 8 + ['dL'] * 51 + ['L'] + [''] * 4 + ['e'] * 5 + [''] * 4 + ['e'] * 5 + [''] * 4 + ['e'] * 5 + [''] * 17 + ['e'] * 4 + [''] * 8 + ['e'] * 5 + [''] * 25 + ['L'] * 38 + ['dL'] * 35 + ['daL'] * 2 + ['aL'] + ['a'] * 5 + [''] * 31)
  yield

  # Check that an NPC got freed.
  assert replay.game.match_flags.stars() > start_stars

  replay.exit()


if __name__ == '__main__':
  replay = ReplayHelper()
  replay.start_game(replay_iter_func)

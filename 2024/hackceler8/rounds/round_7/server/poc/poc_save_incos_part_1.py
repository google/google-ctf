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

# PoC for the save inconsistency challenge, part 1.
# Run this while connecting to the server, then run part 2.

from poc.helper import ReplayHelper


def replay_iter_func(replay):
  # Place player to where the blocks are.
  replay.teleport(2816, 2505)
  # Destroy a block and take its place.
  replay.enqueue([''] * 33 + ['w'] * 14 + ['wd'] * 8 + ['d'] * 49 + [''] * 18 + ['w'] * 27 + ['wa'] * 4 + ['a'] * 24 + [''] * 24 + ['w'] * 5 + ['wd'] * 11 + ['d'] * 6 + ['dL'] * 27 + ['d'] * 35 + [''] * 2 + [' '] + [''] * 60 + [' '] + [''] * 60 + [' '] + [''] * 60 + ['d'] * 33)
  # Wait for the state to save.
  replay.enqueue([''] * 500)
  yield

  replay.exit()


if __name__ == '__main__':
  replay = ReplayHelper()
  replay.start_game(replay_iter_func)

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
  # Enter the arcade and exploit the snake glitch to get the key.
  replay.teleport(1809, 2433)
  replay.enqueue([''] * 19 + ['a'] * 2 + [''] * 6 + ['e'] * 2 + [''] * 205 + ['w'] * 10 + [''] * 23 + ['a'] * 7 + [''] * 29 + ['w'] * 7 + [''] * 25 + ['d'] * 13 + [''] * 27 + ['w'] * 8 + [''] * 53 + ['a'] * 6 + [''] * 5 + ['w'] * 7 + [''] + ['a'] * 10 + [''] * 99 + ['s'] * 6 + [''] * 44 + ['d'] * 7 + [''] * 61 + ['s'] * 6 + [''] * 103 + ['a'] * 9 + [''] * 65 + ['w'] * 7 + ['wd'] * 2 + ['d'] * 14 + [''] * 25 + ['w'] * 12 + [''] * 8 + ['a'] * 8 + [''] * 25 + ['w'] * 12 + [''] * 30 + ['d'] * 8 + [''] * 107 + ['w'] * 8 + [''] * 12 + ['a'] * 9 + [''] * 13 + ['s'] * 6 + [''] * 27 + ['a'] * 9 + [''] * 13 + ['w'] * 5 + [''] * 11 + ['d'] * 6 + [''] * 73 + ['d'] * 3 + [''] * 2)
  yield

  # Make sure we got the key.
  found = False
  for i in replay.game.items:
      if i.name == "key":
          found = True
          break
  assert found

  # Free the NPC using the key.
  replay.enter_map("ruins")
  replay.teleport(1242, 3633)
  replay.enqueue([''] * 90 + ['e'] * 7 + [''] * 5 + ['d'] * 8 + ['dL'] * 51 + ['L'] + [''] * 4 + ['e'] * 5 + [''] * 4 + ['e'] * 5 + [''] * 4 + ['e'] * 5 + [''] * 17 + ['e'] * 4 + [''] * 8 + ['e'] * 5 + [''] * 25 + ['L'] * 38 + ['dL'] * 35 + ['daL'] * 2 + ['aL'] + ['a'] * 5 + [''] * 31)
  yield

  # Make sure we freed the NPC.
  assert replay.game.match_flags.stars() > start_stars
  replay.exit()


if __name__ == '__main__':
  replay = ReplayHelper()
  replay.start_game(replay_iter_func)

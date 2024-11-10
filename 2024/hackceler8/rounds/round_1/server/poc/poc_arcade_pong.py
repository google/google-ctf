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
  # Enter the arcade and use the wrapping glitch to beat the game.
  replay.teleport(1809, 2433)
  replay.enqueue(['e'] + [''] * 60 + [''] * 159 + ['a'] * 7 + [''] * 7 + ['a'] * 4 + [''] * 7 + ['a'] * 5 + [''] * 5 + ['a'] * 4 + [''] * 26 + ['d'] * 16 + [''] * 40 + ['d'] * 4 + [''] * 91 + ['a'] * 7 + [''] * 11 + ['a'] * 6 + [''] * 16 + ['a'] * 3 + [''] * 25 + ['d'] * 10 + [''] * 153 + ['a'] * 11 + [''] * 9 + ['a'] * 4 + [''] * 41 + ['d'] * 18 + [''] * 30 + ['d'] * 13 + [''] * 14 + ['d'] * 3 + [''] * 48 + ['a'] * 24 + [''] * 136 + ['a'] * 6 + [''] * 12 + ['a'] * 6 + [''] * 11 + ['a'] * 4 + [''] * 14 + ['d'] * 11 + [''] * 30 + ['d'] * 9 + [''] * 5 + ['d'] * 7 + [''] * 5 + ['d'] * 5 + [''] * 53 + ['d'] * 56 + [''] * 49 + ['d'] * 6 + [''] * 8 + ['d'] * 99 + [''] * 20 + ['d'] * 85 + [''] * 2 + ['d'] * 6 + [''] * 7 + ['d'] * 29 + [''] + ['a'] * 15 + [''] * 19 + ['a'] * 4 + [''] * 6 + ['a'] * 4 + [''] * 5 + ['a'] * 3 + [''] * 10 + ['a'] * 9 + [''] * 17 + ['a'] * 8 + [''] * 2 + ['d'] * 5 + [''] * 4 + ['a'] * 4 + [''] * 33 + ['d'] * 5 + [''] * 3 + ['d'] * 3 + [''] * 9 + ['d'] * 14 + [''] * 11 + ['d'] * 5 + [''] * 5 + ['d'] * 4 + [''] * 12 + ['a'] + [''] * 8 + ['d'] * 4 + [''] * 6 + ['a'] * 2 + [''] * 4 + ['a'] * 5 + [''] * 13 + ['d'] * 57 + [''] * 6 + ['d'] * 3 + [''] * 18 + ['d'] * 42 + ['da'] * 2 + ['a'] * 16 + [''] + ['d'] * 10 + [''] * 6 + ['d'] * 5 + [''] * 9 + ['a'] * 30 + [''] * 6 + ['a'] * 4 + [''] * 6 + ['a'] * 4 + [''] * 25 + ['a'] * 6 + [''] * 2 + ['a'] * 61 + [''] * 16 + ['d'] * 5 + [''] * 11 + ['a'] * 8 + [''] * 10 + ['d'] * 4 + [''] * 6 + ['a'] * 3 + [''] * 3 + ['a'] * 4 + [''] * 9 + ['a'] * 6 + [''] * 10 + ['a'] * 3 + [''] * 13 + ['a'] * 5 + [''] * 3 + ['a'] * 3 + [''] * 12 + ['a'] * 6 + [''] * 18 + ['d'] * 13 + [''] * 7 + ['d'] * 4 + [''] * 4 + ['d'] * 3 + [''] * 7 + ['d'] * 4 + [''] * 16 + ['a'] * 111 + [''] * 9 + ['a'] * 8 + [''] * 20 + ['d'] * 14 + [''] * 6 + ['d'] * 5 + [''] * 5 + ['d'] * 5 + [''] * 4 + ['d'] * 2 + [''] * 22 + ['d'] * 6 + [''] * 47 + ['a'] * 13 + [''] * 5 + ['a'] * 3 + [''] * 5 + ['a'] * 7 + [''] * 3 + ['a'] * 3 + [''] * 12 + ['a'] * 67 + [''] * 42 + ['d'] * 3 + [''] * 37 + ['a'] * 27 + [''] * 6 + ['a'] * 4 + [''] * 5 + ['a'] * 8 + [''] * 5 + ['a'] * 3 + [''] * 5 + ['a'] * 4 + [''] * 4 + ['a'] * 4 + [''] * 9 + ['d'] * 3 + [''] * 31 + ['d'] * 8 + [''] * 211)
  yield

  # Make sure we got the key.
  found = False
  for i in replay.game.items:
      if i.name == "key":
          found = True
          break
  assert found

  # Free the NPC using the key.
  replay.enter_map("beach")
  replay.teleport(5344, 720)
  replay.enqueue([''] * 89 + ['L'] * 6 + ['La'] * 65 + ['L'] * 17 + ['Ld'] * 17 + ['L'] * 14 + ['Le'] * 4 + ['L'] * 5 + ['Ld'] * 60 + ['e'] * 3 + [''] * 3 + ['e'] * 3 + [''] * 4 + ['e'] * 3 + [''] * 3 + ['e'] * 4 + [''] * 39 + ['d'] * 33 + ['da'] + ['a'] * 6 + [''] * 34 + ['￩'] * 82)
  yield
  # Make sure we freed the NPC.
  assert replay.game.match_flags.stars() > start_stars
  replay.exit()


if __name__ == '__main__':
  replay = ReplayHelper()
  replay.start_game(replay_iter_func)

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
  replay.enqueue([''] * 38 + ['e'] * 6 + [''] * 10 + ['a'] * 7 + [''] + ['e'] * 4 + [''] * 113 + ['d'] + ['sd'] * 56 + ['d'] * 40 + [''] * 10 + [' '] * 12 + [''] * 35 + ['a'] * 19 + ['a '] * 6 + ['a'] * 4 + ['a '] * 6 + ['a'] * 3 + ['a '] * 9 + ['a'] * 9 + [''] * 3 + ['s'] * 77 + [''] * 80 + ['d'] * 7 + [''] * 4 + ['d'] * 8 + [''] * 66 + ['a'] * 4 + ['sa'] * 19 + ['s'] * 8 + [''] * 19 + ['s'] * 14 + [''] * 14 + ['s'] * 10 + [''] * 35 + ['s'] + ['sa'] * 22 + ['s'] * 30 + [''] * 8 + ['a'] * 4 + ['sa'] * 12 + ['s'] * 7 + ['s '] * 7 + ['s'] * 32 + ['sa'] * 41 + ['s'] * 7 + ['sa'] * 38 + ['s'] * 5 + [''] * 104 + ['d'] * 16 + [''] * 28 + ['p'] * 7 + [''] * 47 + ['p'] + [''])
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

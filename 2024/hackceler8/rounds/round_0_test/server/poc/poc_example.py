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
  replay.enter_map("beach")
  replay.teleport(3136, 2176)
  # That's one small step for a man, one giant leap for mankind.
  replay.enqueue(['']*120 + ["wd"]*120)

  yield  # Flush the keystrokes

  # Game state assertions
  assert not replay.game.player.dead

  # Wait
  replay.enqueue([''] * 60)
  # Walk back
  replay.enqueue(['La'] * 30)

  yield  # Flush the keystrokes

  # Game state assertions
  assert not replay.game.player.dead

  # Use this to check that an NPC got freed.
  # assert replay.game.match_flags.stars() > start_stars

  # Test completed
  replay.exit()


if __name__ == '__main__':
  replay = ReplayHelper()
  replay.start_game(replay_iter_func)

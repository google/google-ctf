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
  replay.enter_map("cloud")
  replay.teleport(2084, 324)
  # That's one small step for a man, one giant leap for mankind.
  replay.enqueue(['Ld']*90 + ["wd"] + ['Ld']*190)

  yield  # Flush the keystrokes

  # Game state assertions
  assert not replay.game.player.dead

  # grab poison
  replay.enqueue([''] * 140)
  replay.enqueue([' '])
  yield
  assert len(replay.game.player.weapons) > 0

  # continue to next platform on right.
  replay.enqueue(['wd'] + ['Ld']*100)
  # wait to make sure we landed
  replay.enqueue([''] * 30)
  # jump and glide to top platform
  replay.enqueue(['wa'] + ['La']*100 + ([' a'] + ['La']*20)*15)
  # wait to make sure we landed
  replay.enqueue([''] * 30)
  # jump and glide to quackington
  replay.enqueue(['wa'] + ['La']*100 + ([' a'] + ['La']*20)*25)
  replay.enqueue([''] * 60 + ['e'] + [''] + ['e'] + [''] + ['e'] + ['']*90)

  yield

  assert replay.game.match_flags.stars() > start_stars

  # Test completed
  replay.exit()


if __name__ == '__main__':
  replay = ReplayHelper()
  replay.start_game(replay_iter_func)

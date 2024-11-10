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
from poc.punchcard_helper import example

# Workaround if this doesn't work:
# in textbox.py, before
#                    self.text_input.text = self.choices[self.selection]
#            elif self.free_text_active():
# add
#                 from poc.punchcard_helper import example
#                 self.text_input.text = example
# Then run
# python3 -m poc.record --map=cloud --pos=2122,2353
# And talk to the NPC and send an empty textbox input.
def replay_iter_func(replay):
  start_stars = replay.game.match_flags.stars()
  replay.enter_map("cloud")
  replay.teleport(2122, 2353)
  replay.enqueue(['']*90 + ['a'] + ['e'] + [''] + ['e'] + [''] + ['e'] + [''] + ['e'] + [''])
  yield
  while not replay.game.textbox.free_text_active():
    replay.enqueue([''])
    yield
  replay.game.textbox.text_input.text = example
  replay.enqueue([''] + ['N'] + [''])
  yield
  replay.enqueue(['e'] + [''] + ['e'] + [''] + ['e'] + [''])
  replay.enqueue(['']*120)
  yield
  assert replay.game.match_flags.stars() > start_stars
  replay.exit()


if __name__ == '__main__':
  replay = ReplayHelper()
  replay.start_game(replay_iter_func)

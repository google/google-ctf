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
import logging


class Recorder(ReplayHelper):

  def on_tick(self):
    # report every two secs
    if self.game.tics % 120 == 0:
      # Hold 'R' for 1 sec in last 2 secs to reset the recorder.
      if ''.join(self.key_record[-120:]).count('r') >= 60:
        self.key_record = []

      # Show recording
      print(self.compress_recording(self.key_record))
      print()

  def _advance_iter(self):
    if self._replay_iter:
      try:
        next(self._replay_iter)
      except StopIteration:
        logging.info(f'Replay iter finished')
        self._replay_iter = None


if __name__ == '__main__':
  recorder = Recorder()
  def telep(replay):
    if replay.start_map != "":
      replay.game.telep_to_map = replay.start_map
    if replay.start_pos != "":
      replay.game.telep_to_pos = replay.start_pos
    yield
  recorder.start_game(replay_iter_func=telep)

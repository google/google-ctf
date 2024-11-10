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

import argparse
import logging
from typing import Optional

from game import log
from game.engine.keys import Keys
from game.venator import Venator
from game.venator_gui import Hackceler8
import game.network as network
import moderngl_window as mglw


mglw._orig_create_parser = mglw.create_parser
def _create_parser():
    root = mglw._orig_create_parser()
    return log.get_argument_parser(root)
mglw.create_parser = _create_parser

class ReplayHelper:

  def __init__(self, suppress_sync_log=False):
    self.key_record = []
    self.key_queue = []
    self.text_queue = []
    self.game = None
    self.gui = None
    self.suppress_sync_log = suppress_sync_log
    self.start_map = None
    self.start_pos = None
    self.slowdown_rate = 1
    self.slowdown_ticks = 0

    self._replay_finished = False
    self._replay_finished_count = 0
    self._replay_iter = None

  def enqueue(self, keys: list[str]):
    """Push some keys to the queue to be replayed.

    Encoding rules: * Letters should be lowercase. * Capital L is LSHIFT. *
    Capital E is ESCAPE. * Capital N is ENTER. * " " is SPACE. * Keys for
    different ticks could be:

        Different elements in the list: ['wd', 'wa']
        You can also include input for the dialogue box: [('e', 'Hello!'), 'N']

    For example, "w,Lwd,," means "w" is pressed in the first tick,
    left shift & "w" & "d" is pressed in the second tick, and nothing is
    pressed in the third and forth ticks.
    """
    if len(keys) == 0:
      return
    text_input = [a[1] if type(a) is tuple else None for a in keys]
    keys = [a[0] if type(a) is tuple else a for a in keys]
    keys = [set(map(Keys.from_serialized, k)) for k in keys]
    text_input = text_input[::-1]
    keys = keys[::-1]
    self.key_queue = keys + self.key_queue
    self.text_queue = text_input + self.text_queue
    self._replay_finished = False

  def last_queued_tick(self):
    'Return the scheduled tick of the last queued key.'
    return len(self.key_record) + len(self.key_queue)

  def exit(self):
    logging.info('Terminating PoC')

  def on_tick(self):
    """Callback for every ticks."""
    pass

  def on_start(self):
    """Called once when the game starts."""
    pass

  def on_replay_finished(self, count):
    """Called when the key queue is fully flushed."""
    pass

  # === Predefined actions start ===

  def enter_map(self, name):
    self.game.telep_to_map = name

  def teleport(self, x, y):
    self.game.telep_to_pos = (x, y)

  def compress_recording(self, record: list[str]):
    """Compress the recorded key list and generate code for replay enqueue.

    This function expects to take `self.key_record` or its slice.
    """
    if len(record) == 0:
      return '[]'

    # Dedup same keys
    compressed = [[record[0], 1]]
    for key in record[1:]:
      if key == compressed[-1][0]:
        compressed[-1][1] += 1
      else:
        compressed.append([key, 1])

    # Generate list code
    segments = []
    for key, count in compressed:
      if count == 1:
        segments.append(f'[{repr(key)}]')
      else:
        segments.append(f'[{repr(key)}] * {count}')
    return '[' + ' + '.join(segments) + ']'

  def _advance_iter(self):
    if self._replay_iter:
      try:
        next(self._replay_iter)
      except StopIteration:
        logging.info(f'Replay iter finished')
        self._replay_iter = None
        exit(0)

  def start_game(self, replay_iter_func=None):
    """Run the game!

    `replay_iter_func` is the main function of the replay script, it should
    return an iterator. (i.e. use yield to synchronize)

    The iterator is initialized and advanced once when the game starts, and
    then advanced every time when the key queue is fully flushed.

    When the replay_iter_func is None, the helper can still be controlled
    with pre-enqueued keystrokes, or using the callback interface.
    """
    assert self.game is None, 'already started'
    assert self.gui is None, 'already started'

    helper = self

    class ReplayVenator(Venator):

      def tick(self):
        helper.slowdown_ticks += 1
        if helper.slowdown_ticks >= helper.slowdown_rate:
          helper.slowdown_ticks = 0
        else:
          return
        helper.on_tick()

        if len(helper.key_queue) == 0 and not helper._replay_finished:
          if not helper.suppress_sync_log:
            logging.info(
                'Replay step '
                f'{helper._replay_finished_count} '
                f'finished at tick {helper.game.tics}'
            )
          helper._replay_finished = True
          helper.on_replay_finished(helper._replay_finished_count)
          helper._replay_finished_count += 1
          helper._advance_iter()

          # Release all the keys after replay is finished.
          if len(helper.key_queue) == 0:
            self.raw_pressed_keys: set[Keys] = set()

        if len(helper.key_queue):
          self.raw_pressed_keys = set(helper.key_queue.pop())
        if len(helper.text_queue):
          text = helper.text_queue.pop()
          if text is not None:
            self.textbox.text_input.text = text
        super().tick()
        keys: list[Keys] = sorted(self.raw_pressed_keys, reverse=True)
        keys: str = ''.join([i.serialized if i is not None else "" for i in keys])
        helper.key_record.append(keys)

    class ReplayGui(Hackceler8):
      def setup_game(self):
        self.game = ReplayVenator(self.net, is_server=False)
        helper.game = self.game
        helper.gui = self
        helper.on_start()
        if replay_iter_func:
          helper._replay_iter = iter(replay_iter_func(helper))
          helper._advance_iter()

      def __init__(self, **kwargs):
        log.setup_logging(self.argv, file_prefix='client')
        net = None
        if not self.argv.standalone:
            net = network.NetworkConnection.create_client(
                self.argv.hostname,
                self.argv.port,
                self.argv.cert,
                self.argv.key,
                self.argv.ca,
            )
        helper.start_map = self.argv.map
        helper.start_pos = None
        if self.argv.pos != "":
          helper.start_pos = self.argv.pos.split(",")
          helper.start_pos[0] = int(helper.start_pos[0])
          helper.start_pos[1] = int(helper.start_pos[1])
        helper.slowdown_rate = self.argv.slowdown
        super().__init__(net=net, **kwargs)

      @classmethod
      def add_arguments(cls, parser: argparse.ArgumentParser):
        parser.add_argument(
            '--hostname', nargs='?', default='localhost', help='Server address'
        )
        parser.add_argument(
            '--port', nargs='?', type=int, default=8888, help='Server port'
        )
        parser.add_argument(
            '--cert',
            nargs='?',
            default='ca/dev-team.crt',
            help='Path to client cert',
        )
        parser.add_argument(
            '--key',
            nargs='?',
            default='ca/dev-team.key',
            help='Path to client key',
        )
        parser.add_argument(
            '--ca', default='ca/CA-devel.crt', help='Path to CA .crt file'
        )
        parser.add_argument(
            '--standalone',
            action='store_true',
            default=False,
            help='Run locally (without connecting to a dedicated server)',
        )
        parser.add_argument(
            '--map', nargs='?', default='', help='Starting map for the recording',
        )
        parser.add_argument(
            '--pos', nargs='?', default='', help='Starting position (format: x,y) for the recording',
        )
        parser.add_argument(
            '--slowdown', nargs='?', type=int, default=1, help='Slowdown rate to apply for the recording'
        )

    logging.getLogger('PIL').setLevel(logging.WARNING)
    mglw.run_window_config(ReplayGui)

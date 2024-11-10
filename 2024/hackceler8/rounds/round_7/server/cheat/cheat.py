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
import os
from game import log, venator
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

class CheatVenator(Venator):
    def tick(self):
        if self.cheat.frame_by_frame:
            if self.cheat.next_frame:
                self.cheat.next_frame = False
            else:
                return
        self.cheat.slowdown_ticks += 1
        if self.cheat.slowdown_ticks >= self.cheat.slowdown_rate:
            self.cheat.slowdown_ticks = 0
        else:
            return

        if self.cheat.replay_queue is None:
            self.cheat.key_queue.append(self.raw_pressed_keys.copy())
            # Save keys every 5s when the player is alive.
            if self.player is not None and not self.cheat.player_dead and (self.player.dead or self.tics % 20 == 0):
                self.cheat.player_dead = self.player.dead
                print(f"CHEAT: Saving keypresses to {self.cheat.filename}")
                with open(f"{self.cheat.filename}", "a") as f:
                    for ks in self.cheat.key_queue:
                        f.write(",".join([str(k) for k in ks]) + "\n")
                self.cheat.key_queue = []
        else:
            print("CHEAT: Replaying keys from file...")
            for k in self.cheat.replay_queue:
                self.raw_pressed_keys = k
                super().tick()
            print("CHEAT: Finished replaying")
            print(f"CHEAT: Saving keypresses to {self.cheat.filename}")
            with open(f"{self.cheat.filename}", "a") as f:
                for ks in self.cheat.replay_queue:
                    f.write(",".join([str(k) for k in ks]) + "\n")
            self.cheat.replay_queue = None
            self.raw_pressed_keys = set()
            self.cheat.frame_by_frame = True
            return
        super().tick()

class CheatClient(Hackceler8):

    def __init__(self, **kwargs):
        self.slowdown_rate = 1
        self.slowdown_ticks = 0
        self.frame_by_frame = False
        self.next_frame = False
        self.key_queue = []
        self.replay_queue = None
        self.player_dead = False
        self.game = None
        self.filename = None
        net = self.setup()
        super().__init__(net=net, **kwargs)

    def setup_game(self):
        self.game = CheatVenator(self.net, endpoint_type=venator.EndpointType.CLIENT)
        self.game.cheat = self

    def on_key_press(self, symbol: int, modifiers: int):
        super().on_key_press(symbol, modifiers)
        symbol = Keys.from_ui(symbol)

        if self.game.textbox is not None:
            # Don't interfere with dialogue.
            return
        if symbol == Keys.DOWN:
            self.slowdown_rate += 1
            print(f"CHEAT: Slowdown rate increased to {self.slowdown_rate}")
        elif symbol == Keys.UP:
            self.slowdown_rate = max(1, self.slowdown_rate-1)
            print(f"CHEAT: Slowdown rate decreased to {self.slowdown_rate}")
        elif symbol == Keys.BACKSPACE:
            self.frame_by_frame = not self.frame_by_frame
            state = "Entering" if self.frame_by_frame else "Exiting"
            print(f"CHEAT: {state} frame-by-frame mode")
        elif symbol == Keys.RIGHT:
            if self.frame_by_frame:
                # Ready to go to the next frame.
                self.next_frame = True

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
            '--replay', nargs='?', default='', help='file to replay key presses from',
        )
        parser.add_argument(
            '--stop-replay-before', nargs='?', type=int, default=0, help='number of frames to omit from the end of the replay',
        )

    def setup(self):
        self.filename = f"cheat/keys_{os.getpid()}.txt"
        log.setup_logging(self.argv, file_prefix='client')

        logging.getLogger('arcade').setLevel(logging.WARNING)
        logging.getLogger('PIL').setLevel(logging.WARNING)

        if self.argv.replay != '':
            self.replay_queue = []
            with open(self.argv.replay, "r") as f:
                for line in f.read().split("\n"):
                    if len(line) == 0:
                        self.replay_queue.append(set())
                    else:
                        self.replay_queue.append(set([eval(k) for k in line.split(",")]))
            if self.argv.stop_replay_before > 0:
                if len(self.replay_queue) > self.argv.stop_replay_before:
                    self.replay_queue = self.replay_queue[:-self.argv.stop_replay_before]
                else:
                    self.replay_queue = None

        net = None
        if not self.argv.standalone:
                net = network.NetworkConnection.create_client(
                        self.argv.hostname,
                        self.argv.port,
                        self.argv.cert,
                        self.argv.key,
                        self.argv.ca,
                )
        return net

if __name__ == '__main__':
    logging.getLogger('PIL').setLevel(logging.WARNING)
    mglw.run_window_config(CheatClient)

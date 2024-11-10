#!/usr/bin/env python
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

# numpy's multithreading is too smart for its own good
# do this _before_ it gets imported
import os
os.environ['OMP_NUM_THREADS'] = '1'

from game import log
from game import venator_gui
from game import network
import moderngl_window as mglw


# A silly monkeypatch to work around mglw not allowing to pass in a parent parser
mglw._orig_create_parser = mglw.create_parser
def _create_parser():
    root = mglw._orig_create_parser()
    return log.get_argument_parser(root)
mglw.create_parser = _create_parser

class Hx8Client(venator_gui.Hackceler8):
    def __init__(self, **kwargs):
        log.setup_logging(self.argv, file_prefix='client')
        net = None
        if not self.argv.standalone:
            net = network.NetworkConnection.create_client(
                self.argv.hostname,
                self.argv.port,
                self.argv.cert,
                self.argv.key,
                ca=self.argv.ca,
            )

            if net is None:
                logging.fatal(
                    'Connecting to server failed, pass --standalone if you want to run'
                    ' the game without a server.'
                )
                raise SystemExit()

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


def main():
    logging.getLogger('PIL').setLevel(logging.WARNING)
    mglw.run_window_config(Hx8Client)


if __name__ == '__main__':
    main()

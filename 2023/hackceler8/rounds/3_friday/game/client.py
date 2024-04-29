# Copyright 2023 Google LLC
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

import ludicer_gui
import network
import log


def main():
    parser = argparse.ArgumentParser(prog='client', parents=[log.get_argument_parser()])
    parser.add_argument('hostname', nargs='?', default='localhost', help='Server address')
    parser.add_argument('port', nargs='?', type=int, default=8888, help='Server port')
    parser.add_argument('cert', nargs='?', default='../ca/dev-team', help='Path to client cert (without .key/.crt suffix)')
    parser.add_argument('--ca', default='../ca/CA-devel.crt', help='Path to CA .crt file')
    parser.add_argument('--standalone', action='store_true', default=False, help='Run locally (without connecting to a dedicated server)')

    args = parser.parse_args()
    log.setup_logging(args, file_prefix='client')

    logging.getLogger("arcade").setLevel(logging.WARNING)
    logging.getLogger("PIL").setLevel(logging.WARNING)

    net = None
    if not args.standalone:
        net = network.NetworkConnection.create_client(
            args.hostname, args.port, args.cert, ca=args.ca,
        )

        if net is None:
            logging.fatal("Connecting to server failed, pass --standalone if you want to run the game without a server.")
            raise SystemExit()

    window = ludicer_gui.Hackceler8(net)
    window.run()


if __name__ == "__main__":
    main()

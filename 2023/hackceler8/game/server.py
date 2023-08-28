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
import json
import logging
import os
import sys

import log
import ludicer
import network


def extract_state(msg):
    try:
        d = json.loads(msg.decode())
    except Exception as e:
        logging.critical(f"Failed to decode message: {e}")
        raise
    return d.get("tics", None), d.get("state", None), d.get("keys", None), d.get("text_input", None)


def integrity_check(gs, msg):
    _ticks, state, keys, text_input = extract_state(msg)
    gs.pressed_keys = set(keys)
    if text_input is not None:
        gs.set_text_input(text_input)
    gs.tick()
    if gs.state_hash != state:
        logging.critical("Out of sync, cheating detected!")
        return False
    return True

def main():
    parser = argparse.ArgumentParser(prog='server', parents=[log.get_argument_parser()])
    parser.add_argument('--hostname', default='0.0.0.0', help='Server bind')
    parser.add_argument('port', nargs='?', type=int, default=8888, help='Server port')
    parser.add_argument('team', nargs='?', default='dev-team', help='team name (certificate CN)')

    parser.add_argument('cert', nargs='?', default='../ca/dev-team', help='Path to client cert (without .key/.crt suffix)')

    args = parser.parse_args()
    log.setup_logging(args, file_prefix='server')
    logging.getLogger("arcade").setLevel(logging.WARNING)
    logging.getLogger("PIL").setLevel(logging.WARNING)

    net = network.NetworkConnection.create_server(
        args.hostname, args.port,
        expected_cn=args.team,
    )
    logging.info(f"Server running on {args.hostname}:{args.port} for {args.team}")

    while True:
        try:
            connection, addr = net.accept()
        except Exception as e:
            logging.critical(f"Exception accepting new client: {e}")
            continue

        logging.info(f"New connection from {addr}")

        game_session = ludicer.Ludicer(None, is_server=True)

        while True:
            logging.debug("receiving")
            try:
                message = connection.recv_one()
            except Exception as e:
                logging.critical(f"Exception receiving packet: {e}")
                break

            try:
                if not integrity_check(game_session, message):
                    break
            except:
                logging.exception("Exception when handling client packet")
                break

if __name__ == '__main__':
    main()

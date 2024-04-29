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
import multiprocessing
import time

import log
import ludicer
import network
import scheduler

from engine.state import SaveFile

MAX_TPS = 60.0

game_running = False


def extract_state(msg):
    try:
        d = json.loads(msg.decode())
    except Exception as e:
        logging.critical(f"Failed to decode message: {e}")
        raise
    return (d.get("tics", None), d.get("state", None), d.get("keys", None),
            d.get("seed", None), d.get("text_input", None),
            d.get("llm_ack", False))


def integrity_check(gs, msg):
    _ticks, state, keys, seed, text_input, llm_ack = extract_state(msg)
    gs.raw_pressed_keys = set(keys)
    if seed is not None:
        gs.rand_seed = seed
    if text_input is not None:
        gs.set_text_input(text_input)
    gs.llm.ack_recvd = llm_ack
    gs.tick()
    if gs.state_hash != state:
        logging.critical("Out of sync, cheating detected!")
        return False
    return True


def game_tick(connection, game_session):
    global game_running
    logging.debug("receiving")
    try:
        message = connection.recv_one()
    except Exception as e:
        logging.critical(f"Exception receiving packet: {e}")
        game_running = False
        return

    try:
        if not integrity_check(game_session, message):
            game_running = False
            connection.send_one(json.dumps({"u_cheat": True}).encode())
            return
    except Exception as e:
        logging.exception(f"Exception when handling client packet: {e}")
        game_running = False
        return


def startup(connection):
    try:
        s = SaveFile()
        json_packet = s.load()
        logging.info(f"Got save state: {json_packet}")
    except FileNotFoundError:
        logging.critical("no save file found")
        return
    except Exception as e:
        logging.critical(f"error reading save file: {e}")
        return

    try:
        connection.send_one(json.dumps({'save_state':json_packet}).encode())
    except Exception as e:
        logging.exception(f"Exception when handling client packet: {e}")
        return


def game_loop(connection):
    global game_running

    game_session = ludicer.Ludicer(net=connection, is_server=True)
    game_running = True

    startup(connection)

    clock = scheduler.TickScheduler(MAX_TPS, 5.0)
    clock.start()

    while game_running:
        game_tick(connection, game_session)
        clock.tick()
        t = clock.get_sleep_time()
        if t > 0.0:
            time.sleep(t)


def main():
    parser = argparse.ArgumentParser(prog='server', parents=[log.get_argument_parser()])
    parser.add_argument('--hostname', default='0.0.0.0', help='Server bind')
    parser.add_argument('port', nargs='?', type=int, default=8888, help='Server port')
    parser.add_argument('team', nargs='?', default='dev-team',
                        help='team name (certificate CN)')

    parser.add_argument('cert', nargs='?', default='../ca/dev-team',
                        help='Path to server cert (without .key/.crt suffix)')
    parser.add_argument('--ca', default='../ca/CA-devel.crt',
                        help='Path to CA .crt file')
    parser.add_argument('--keylog', default=None, help='Path to keylog file')


    parser.add_argument('--stateport', default=1337, type=int, help='State server port (HTTP)')
    args = parser.parse_args()
    log.setup_logging(args, file_prefix='server')
    logging.getLogger("arcade").setLevel(logging.WARNING)
    logging.getLogger("PIL").setLevel(logging.WARNING)

    net = network.NetworkConnection.create_server(
        args.hostname, args.port,
        cert=args.cert,
        ca=args.ca,
        expected_cn=args.team,
        keylog_filename=args.keylog,
    )
    logging.info(f"Server running on {args.hostname}:{args.port} for {args.team}")

    child_process = None
    stopped = False
    with network.StatusServer(("", args.stateport), args.team) as status_server:
        try:
            while True:
                try:
                    connection, addr = net.accept()
                except Exception as e:
                    logging.critical(f"Exception accepting new client: {e}")
                    continue

                logging.info(f"New connection from {addr}")

                if child_process is not None:
                    logging.info("Stopping previous instance")
                    child_process.kill()
                    child_process.join()

                logging.info("Spawning game_loop")
                stopped = False
                child_process = multiprocessing.Process(target=game_loop,
                                                 args=[connection])
                child_process.start()
        finally:
            # Make sure current connection stops in cases where there is an exception
            # on the main thread (i.e. CTRL+C).
            stopped = True


if __name__ == '__main__':
    main()

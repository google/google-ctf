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

# New game server: A simple I/O accepting binary

import argparse
import json
import logging
import time
import sys
import struct
import traceback

import ludicer
import scheduler

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
        print(f"Exception receiving packet: {e}", file=sys.stderr)
        game_running = False
        return

    try:
        if not integrity_check(game_session, message):
            game_running = False
            connection.send_one(json.dumps({"u_cheat": True}).encode())
            return
    except Exception as e:
        print(f"Exception when handling client packet: {e}", file=sys.stderr)
        game_running = False
        return


def game_loop(connection):
    global game_running

    game_session = ludicer.Ludicer(net=connection, is_server=True)
    game_running = True

    clock = scheduler.TickScheduler(MAX_TPS, 5.0)
    clock.start()

    while game_running:
        game_tick(connection, game_session)
        clock.tick()
        t = clock.get_sleep_time()
        if t > 0.0:
            time.sleep(t)

class IOConnection:
    def recv_one(self):
        size_bytes = sys.stdin.buffer.read(4)
        size = struct.unpack(">I", size_bytes)[0]
        ret = sys.stdin.buffer.read(size)
        assert len(ret) == size, "Unexpected packet length"
        try:
            d = json.loads(ret.decode())
            keys = d.get("keys", [])
            print(" ".join(["%02x"%a for a in keys]), file=sys.stderr)
        except Exception as e:
            print(e, file=sys.stderr)
        return ret

    def send_one(self, msg):
        d = json.loads(msg.decode())
        if "flag" in d:
            print("Sent flag to player: %s" % d["flag"], file=sys.stderr)
        sys.stdout.write(struct.pack(">I", len(msg)).decode("utf-8"))
        sys.stdout.write(msg.decode("utf-8"))
        sys.stdout.flush()


def main():
    parser = argparse.ArgumentParser(prog='server')
    args = parser.parse_args()
    logging.disable(logging.CRITICAL) # IO is used for client-server interaction
    try:
      game_loop(IOConnection())
    except Exception as e:
      traceback.print_exc()
      print(e, file=sys.stderr)


if __name__ == '__main__':
    main()

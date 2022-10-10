# Copyright 2022 Google LLC
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

import datetime
import multiprocessing
import os
import signal
import socket
import ssl
import sys
import time
import traceback
from typing import Optional

SRC_DIR = os.path.dirname(os.path.realpath(__file__))

import settings
settings.environ = 'server'
import environ
environ.SRC_DIR = SRC_DIR

import arcade
import context_aware_serialization
import difflib
import game as game_mod
import keys
import map_loader
import messages
import network
import serialization_pb2
import serialize
import validation
import persistent_state
import save as save_lib
import score_server

HOST = "0.0.0.0"
TEAM = sys.argv[1] if len(sys.argv) > 1 else 'teamTEST'
PORT = int(sys.argv[2]) if len(sys.argv) > 2 else 8888

SECRET_KEY = open("./server_secret", "rb").read()

# The maximum amount that the client can be ahead of the server.
MAX_DRIFT_S = 1.0

score_server.start(PORT+1)


@messages.check_valid
def validate_gamestate(client_gamestate):
    comparison = validation.Validate(client_gamestate, environ.game)
    if comparison is not None:
        msg = 'failed to validate client game state, sending stop message to client' + "\n".join(
            difflib.Differ().compare(comparison[0].split("\n"), comparison[1].split("\n")))
        # now drop the client
        net.send("stop_diff", serialize.SerializableTuple(comparison))
        raise RuntimeError(msg)
    net.send("is_valid", None)

@messages.tick
def tick(input):
    tnum = environ.game.tick_number + 1
    if not settings.uncap_fps and not check_throttle(tnum):
        msg = f"Client tick {tnum} is too far in the future."
        net.send("stop", msg)
        raise RuntimeError(msg)
    environ.game.held_keys = set(input["inputs"])
    environ.game.tick()

    if environ.game.request_map_change is not None:
        request_map_change = environ.game.request_map_change
        environ.game.request_map_change = None

        if request_map_change["map_name"] and not games[request_map_change["map_name"]] is environ.game:
            new_game: game_mod.Game = games[request_map_change["map_name"]]
            new_game.tick_number = environ.game.tick_number
            old_player = environ.game.player
            new_game.held_keys = environ.game.held_keys
            environ.game = new_game
            environ.game.player.level_persistent = old_player.level_persistent

        destination_name = request_map_change.get("destination", "")
        if destination_name:
            destination = environ.game.root.find_by_name(destination_name)
            environ.game.player.transform.position.x = destination.transform.position.x
            environ.game.player.transform.position.y = destination.transform.position.y

@messages.exit_chat
def exit_chat(_):
    print("exit_chat")
    environ.game.now_talking_to = None

@messages.send_chat
def send_chat(txt):
    print("send_chat", txt)
    environ.game.now_talking_to.on_query(sys.intern(txt))

@messages.request_save
def save(_):
    print(f"Save allow status: now {environ.game.save_allowed}, game={environ.game}")
    if not environ.game.save_allowed:
        net.send("stop", "Can only save at a save point.")
        raise RuntimeError("Can only save at a save point.")
    msg = save_lib.make_blob(games, environ.game)
    msg += validation.get_signature(msg, SECRET_KEY)
    net.send("request_save_response", msg)


@messages.request_load
def load_save_state(save):
    valid, msg = validation.verify_signature(save, SECRET_KEY)

    if not valid:
        # save state has invalid signature.
        net.send("stop", "invalid save state")
        raise RuntimeError("Invalid game state on load")

    global games
    games, game = save_lib.load_blob(msg, games)

    environ.game = game
    mark_start(game.tick_number)
    # tell client that we loaded the game and it can resume execution.
    net.send("request_load_response", b"")


@messages.request_load_persistent_state
def load_persistent_state(_):
    try:
        with open("./persistent_state", "rb") as f:
            save = f.read()
    except FileNotFoundError:
        persistent_state.persistent_state = persistent_state.PersistentState()
        net.send("request_load_persistent_state_response", persistent_state.persistent_state)
        return

    save = serialization_pb2.SerializedPackage.FromString(save)
    persistent_state.persistent_state = serialize.Deserialize(save, None)
    net.send("request_load_persistent_state_response", persistent_state.persistent_state)


@messages.request_save_persistent_state
def save_persistent_state(_):
    try:
        data = serialize.Serialize(persistent_state.persistent_state).SerializeToString()
        with open("./persistent_state", "wb") as f:
            f.write(data)
        net.send("request_save_persistent_state_response", "Persistent state saved.")
    except Exception as e:
        net.send("request_save_persistent_state_response", "Could not save persistent state: " + str(e))

@messages.use_item
def use_item(item_idx):
    environ.game.player.use_item(item_idx)

start_time: float = float('inf')
start_tick: int = 0

def mark_start(tick: int):
    global start_time
    global start_tick
    start_tick = tick
    start_time = time.time()


def check_throttle(tick: int):
    delta_t = time.time() - start_time
    delta_f = tick - start_tick
    if (delta_f / game_mod.FPS) - delta_t > MAX_DRIFT_S:
        return False
    return True


def _child_game(conn: socket.socket, traffic_log_file):
    mark_start(tick=0)
    global net
    net = network.NetworkConnection(conn, server=True, traffic_log_file=traffic_log_file)

    global games
    games = {}
    for map_name, map_path in map_loader.list_maps().items():
        games[map_name] = map_loader.load_map(map_path)

    game = games["main"]
    # access this variable once, such that it is not `None` during
    # serialization on the server side. This is needed during
    # validation.
    game.player
    environ.game = game
    del game
    environ.start_timestamp = start_time

    net.run()


traffic_log_file = os.environ.get('H8_TRAFFIC_LOG_FILE', '')
def _child_game_log(conn: socket.socket):
    if not traffic_log_file:
        return _child_game(conn, None)

    with open(traffic_log_file, 'ab', buffering=0) as lf:
        lf.write(f'Hackceler8 traffic log for {TEAM} - PID {os.getpid()} - {datetime.datetime.now().isoformat()}\n\n'.encode())
        return _child_game(conn, lf)


def _child(current_client_pid: multiprocessing.Value, sock: socket.socket):
    try:
        sock.settimeout(1)
        conn = network.wrap_and_handshake(sock,
                                          server=True,
                                          my_cert=cert_base,
                                          expected_client=TEAM)
        conn.settimeout(None)
    except Exception as e:
        print('SSL handshake error')
        traceback.print_exc()
        return
    # Handshake successful, kill previous client if there is any.
    with current_client_pid.get_lock():
        old_pid = current_client_pid.value
        if old_pid != 0:
            print(f"Booting previous client (pid={old_pid})")
            os.kill(old_pid, signal.SIGKILL)
            current_client_pid.value = os.getpid()
    _child_game_log(conn)

def sigchld_handler(signum, frame):
    # Reap exited children
    while True:
        pid, status = os.waitpid(-1, os.WNOHANG)
        if pid == 0:
            # waitpid with WNOHANG returns (0, 0) if there are no children to
            # wait for.
            break

signal.signal(signal.SIGCHLD, sigchld_handler)

cert_base = os.environ.get('H8_SERVER_CERT', 'test_server')
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((HOST, PORT))
    s.listen()

    current_client_pid = multiprocessing.Value('i', 0, lock=True)
    while True:
        sock, addr = s.accept()
        print(f"New connection from {addr}")
        with sock:
            new_child = os.fork()
            # https://wiki.openssl.org/index.php/Random_fork-safety
            # probably not needed anymore but let's be extra safe
            with open('/dev/urandom', 'rb') as f:
                ssl.RAND_add(f.read(32), 32)
            if new_child == 0:
                _child(current_client_pid, sock)
                break

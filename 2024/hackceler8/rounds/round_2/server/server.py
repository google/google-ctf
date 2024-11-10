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
import json
import logging
import multiprocessing
import os
import time

from game import log, venator, network, scheduler
from game.components.items import Item
from game.engine.keys import Keys
from game.engine.save_file import SaveFile

MAX_TPS = 60.0

GAME_RUNNING = False


def extract_state(msg):
  try:
    msg = json.loads(msg.decode())
  except Exception as ex:
    logging.critical(f"Failed to decode message: {ex}")
    raise
  return (
      msg.get("tics", None),
      msg.get("state", None),
      msg.get("keys", None),
      msg.get("text_input", None),
  )


def integrity_check(game_session, msg):
  _ticks, state, keys, text_input = extract_state(msg)
  game_session.raw_pressed_keys = set(Keys.from_serialized(i) for i in keys)
  if text_input is not None:
    game_session.set_text_input(text_input)
  # TODO BEFORE RELEASING TO PLAYERS: Remove block start
  game_session.telep_to_map = json.loads(msg.decode()).get("telep_to_map_5272aa6795f5732", None)
  game_session.telep_to_pos = json.loads(msg.decode()).get("telep_to_pos_5272aa6795f5732", None)
  # TODO BEFORE RELEASING TO PLAYERS: Remove block end
  game_session.tick()
  if game_session.state_hash != state:
    logging.critical("Out of sync, cheating detected!")
    return False
  return True


def game_tick(connection, game_session):
  global GAME_RUNNING
  logging.debug("receiving")
  try:
    message = connection.recv_one()
  except Exception as ex:
    logging.critical(f"Exception receiving packet: {ex}")
    GAME_RUNNING = False
    return

  try:
    if not integrity_check(game_session, message):
      GAME_RUNNING = False
      connection.send_one(json.dumps({"u_cheat": True}).encode())
      return
  except Exception as ex:
    logging.exception(f"Exception when handling client packet: {ex}")
    GAME_RUNNING = False
    return


def startup(connection, save_file_path, save_version, extra_items):
  try:
    s = SaveFile(save_file_path, save_version, extra_items)
    json_packet = s.load()
    logging.info(f"Got save state: {json_packet}")
  except FileNotFoundError:
    logging.critical("no save file found")
    return
  except Exception as ex:
    logging.critical(f"error reading save file: {ex}")
    return

  try:
    connection.send_one(json.dumps({"save_state": json_packet}).encode())
  except Exception as ex:
    logging.exception(f"Exception when handling client packet: {ex}")
    return


def game_loop(connection, save_file_path, save_version, extra_items):
  global GAME_RUNNING

  game_session = venator.Venator(
      net=connection, is_server=True, save_file_path=save_file_path,
      save_version=save_version, extra_items=extra_items
  )
  GAME_RUNNING = True

  startup(connection, save_file_path, save_version, extra_items)

  clock = scheduler.TickScheduler(MAX_TPS, 5.0)
  clock.start()

  while GAME_RUNNING:
    game_tick(connection, game_session)
    clock.tick()
    sleep_time = clock.get_sleep_time()
    if sleep_time > 0.0:
      time.sleep(sleep_time)


def main():
  parser = argparse.ArgumentParser(
      prog="server", parents=[log.get_argument_parser()]
  )
  parser.add_argument("--hostname", default="0.0.0.0", help="Server bind")
  parser.add_argument(
      "--port", nargs="?", type=int, default=8888, help="Server port"
  )
  # TODO BEFORE RELEASING TO PLAYERS: Remove block start
  parser.add_argument(
      "--spectatorport", default=8889, type=int, help="State server port (HTTP)"
  )
  # TODO BEFORE RELEASING TO PLAYERS: Remove block end
  parser.add_argument(
      "--team", nargs="?", default="dev-team", help="team name (certificate CN)"
  )

  parser.add_argument(
      "--cert",
      nargs="?",
      default="ca/dev-team.crt",
      help="Path to server cert",
  )

  parser.add_argument(
      "--key",
      nargs="?",
      default="ca/dev-team.key",
      help="Path to server key",
  )
  parser.add_argument(
      "--ca", default="ca/CA-devel.crt", help="Path to CA .crt file"
  )
  parser.add_argument("--keylog", default=None, help="Path to keylog file")

  parser.add_argument(
      "--stateport", default=1337, type=int, help="State server port (HTTP)"
  )
  parser.add_argument(
      "--save-file", default="save_state", help="Path of the save state file"
  )
  parser.add_argument(
      "--save-version", default="current", type=str, help="The version of the current save file"
  )
  parser.add_argument("--extra-items", nargs="+", help="Additional helpful items to give to the player")
  # TODO BEFORE RELEASING TO PLAYERS: Remove block start
  parser.add_argument('--autogen', action=argparse.BooleanOptionalAction, default=True,
                      help="Whether to re-generate map binaries and other compiled files during startup")
  # TODO BEFORE RELEASING TO PLAYERS: Remove block end
  args = parser.parse_args()
  log.setup_logging(args, file_prefix="server")
  logging.getLogger("arcade").setLevel(logging.WARNING)
  logging.getLogger("PIL").setLevel(logging.WARNING)
  # TODO BEFORE RELEASING TO PLAYERS: Remove block start
  venator.regen_compiled_files = args.autogen
  # TODO BEFORE RELEASING TO PLAYERS: Remove block end

  # Check if this is the correct round's save file
  if os.path.exists(args.save_file):
    with open(args.save_file) as f:
      data = json.load(f)
    if data.get('version') != args.save_version:
      logging.warning("Save file is for other version, deleting")
      os.remove(args.save_file)

  # Create a save state if there is none yet
  if not os.path.exists(args.save_file):
    logging.warning("Save file does not exist yet, creating a new one")
    game_instance = venator.Venator(None, True, args.save_file, args.save_version, args.extra_items)
    game_instance._save()
    del game_instance

  net = network.NetworkConnection.create_server(
      args.hostname,
      args.port,
      cert=args.cert,
      key=args.key,
      ca=args.ca,
      expected_cn=args.team,
      keylog_filename=args.keylog,
  )
  logging.info(f"Server running on {args.hostname}:{args.port} for {args.team}")

  child_process = None
  multiprocessing.set_start_method("fork")
  with network.StatusServer(("", args.stateport), args.team, args.save_file, args.save_version, args.extra_items):
    try:
      while True:
        try:
          connection, addr = net.accept()
        except Exception as ex:
          logging.critical(f"Exception accepting new client: {ex}")
          continue

        logging.info(f"New connection from {addr}")

        if child_process is not None:
          logging.info("Stopping previous instance")
          child_process.kill()
          child_process.join()

        logging.info("Spawning game_loop")
        child_process = multiprocessing.Process(
            target=game_loop, args=[connection, args.save_file, args.save_version, args.extra_items]
        )
        child_process.start()
    finally:
      # Make sure current connection stops in cases where there is an exception
      # on the main thread (i.e. CTRL+C).
      if child_process is not None:
        logging.info("Stopping previous instance")
        child_process.kill()
        child_process.join()


if __name__ == "__main__":
  main()

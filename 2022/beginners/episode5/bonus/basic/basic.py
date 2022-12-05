#!/usr/bin/env python3
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
import hashlib
import json
import os
import queue
import random
import socket
import subprocess
import sys
import tempfile
import threading
import time

script_dir = os.path.dirname(os.path.realpath(__file__))
sys.path.append(f"{script_dir}/../py_common")
import textbuffer

W = textbuffer.TextBuffer.W
H = textbuffer.TextBuffer.H
txt = None

LISTING_NEWEST = 'listing.json'
LISTING_HISTORY = 'history.txt'
HISTORY_BOUNDARY = '-' * 80

CMD_LENGTH_LIMIT = 71

BASIC_UDP_PORT = 23410

BASIC_EXEC = './basic8051emu'

# LineEditor features:
# <LINE> <TEXT> - Place text at a given LINE number.
#                 E.g.: 110 PRINT "ASDF"
# del <LINE>    - Remove line.
#                 E.g.: DEL 110
# list          - List the whole program.
# list <LINE>   - List just one line.
#                 E.g.: LIST 110
# list <LINE>-  - List from this line onward.
#                 E.g.: LIST 110-
# list <LINE>-<LINE> - List line range (inclusive).
# run           - Start the program from first line.
# run <LINE>    - Start the program from given line.
class LineEditor:
  def __init__(self):
    self.version = 0
    self.listing = {}
    self.load_listing()

  def listing_to_text(self):
    output = []
    for line, text in sorted(self.listing.items()):
      output.append(f"{line} {text}\n")

    return ''.join(output)

  def listing_to_text_range(self, start, stop=65536):
    # Short circuit.
    if start == stop:
      try:
        line = self.listing[start]
      except KeyError:
        return ""

      return line + "\n"

    # Full version.
    output = []
    for line, text in sorted(self.listing.items()):
      if line < start:
        continue

      if line > stop:
        break

      output.append(f"{line} {text}\n")

    return ''.join(output)

  def save_listing(self):
    with open(LISTING_NEWEST, "w") as f:
      json.dump({
        "version": self.version,
        "listing": self.listing
      }, f)

  def load_listing(self):
    try:
      with open(LISTING_NEWEST) as f:
        data = json.load(f)
        self.version = data["version"]
        self.listing = { int(ln): text for ln, text in data["listing"].items() }

        print(
            f"note: loaded version {self.version} ({len(self.listing)} lines)."
        )
    except FileNotFoundError:
      return
    except ValueError:
      print("error: value error on newest file!")
    except json.decoder.JSONDecodeError:
      print("error: json decoder error on the newest file!")
      return

  def save_history(self):
    with open(LISTING_HISTORY, "a") as f:
      f.write(f"\n{HISTORY_BOUNDARY} {self.version}\n")
      f.write(self.listing_to_text())

  #def load_history(self, version):
  #maybe implement this

  def save(self):
    self.save_listing()
    self.save_history()
    self.version += 1

  def error(self, s):
    print(f"BASIC ERROR: {s}")
    txt.set_attr(True)
    txt.print("ERROR\x09")
    txt.set_attr(False)
    txt.print(f" {s}\n")

  def set_line(self, line, text):
    if line < 1 or line > 65535:
      self.error("Invalid line number.")
      return

    self.listing[line] = text
    self.save()

  def del_line(self, line):
    if line < 1 or line > 65535:
      self.error("Invalid line number.")
      return

    try:
      del self.listing[line]
      self.save()
    except KeyError:
      self.error("Line didn't exist.")

  def list_all(self):
    txt.print(self.listing_to_text())

  def list_from(self, start):
    if start < 0 or start > 65535:
      self.error("Invalid start line number.")
      return

    txt.print(self.listing_to_text_range(start))

  def list_from_to(self, start, stop):
    if start < 0 or start > 65535:
      self.error("Invalid start line number.")
      return

    if stop < 0 or stop > 65535:
      self.error("Invalid stop line number.")
      return

    be_funny = False
    if start > stop:  # If the user wants reverse, reverse they will get.
      start, stop = stop, start
      be_funny = True

    text = self.listing_to_text_range(start, stop)
    if be_funny:
      lines = text.splitlines()[::-1]
      text = '\n'.join(lines) + '\n'

    txt.print(text)

  def run_worker(self, start_from=None):
    listing = self.listing_to_text()

    with tempfile.NamedTemporaryFile("w") as f:
      if start_from is not None:
        f.write(f"0 goto {start_from}\n")
      f.write(listing)
      f.flush()

      with subprocess.Popen([
              BASIC_EXEC,
              f.name
          ],
          stdout=subprocess.PIPE
      ) as p:
        while True:
          data = p.stdout.read(1)
          if not data:
            break
          data = data.decode()
          txt.print(data)
          sys.stdout.write(data)
          sys.stdout.flush()

  def run(self):
    self.run_worker()

  def run_from(self, start):
    if start < 1 or start > 65535:
      self.error("Invalid start line number.")
      return

    self.run_worker(start)

  def arg_to_int(self, s, show_error=True):
    try:
      return int(s)
    except:
      if show_error:
        self.error("Arg not a number.")
      return None

  def handle_command(self, cmd):
    cmd = cmd.strip()
    if not cmd:
      self.error("Command empty?")
      return

    if len(cmd) > CMD_LENGTH_LIMIT:
      self.error("Command too long.")
      return

    # Easy cases.
    if cmd == "run":
      self.run()
      return

    if cmd == "list":
      self.list_all()
      return

    if cmd == "help":
      txt.print(
          "https://storage.googleapis.com/gctf-h4ck-2022-attachments-project/"
          "Controller%20Datasheet.pdf\n"
      )
      return

    if cmd.replace(' ', '').lower() == "wait6502,1":
      txt.print(bytearray([71, 121, 110, 118, 97, 101, 108, 33, 10]).decode())
      return

    # More complex commands.
    cmd_split = cmd.split(maxsplit=1)
    if len(cmd_split) != 2:
      self.error("Invalid command.")
      return

    cmd = cmd_split[0]
    arg = cmd_split[1]

    if not arg:
      self.error("Missing argument.")
      return

    if cmd == "del":
      line = self.arg_to_int(arg)
      if line is None:
        return
      self.del_line(line)
      return

    if cmd == "run":
      line = self.arg_to_int(arg)
      if line is None:
        return
      self.run_from(line)
      return

    if cmd == "list":
      if '-' in arg:
        start_s, stop_s = arg.split('-', maxsplit=1)
        start_s = start_s.strip()
        stop_s = stop_s.strip()

        start = self.arg_to_int(start_s)
        if start is None:
          return

        if not stop_s:
          self.list_from(start)
          return

        stop = self.arg_to_int(stop_s)
        if stop is None:
          return

        self.list_from_to(start, stop)
        return

      else:
        line = self.arg_to_int(arg)
        if line is None:
          return

        self.list_from_to(line, line)
        return

    # <LINE> <TEXT> only left.
    line = self.arg_to_int(cmd, show_error=False)
    if line is None:
      self.error("Unknown command.")
      return

    self.set_line(line, arg)

def main():
  # Setup the screen.
  global txt
  txt = textbuffer.TextBuffer(23400)
  txt.badlang_checks_enabled = True
  txt.set_show_alive(True)

  edit = LineEditor()

  txt.print("READY\n")

  s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
  s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
  s.bind(("127.0.0.1", BASIC_UDP_PORT))
  print(f"note: listening on UDP:{BASIC_UDP_PORT}")

  while True:
    cmd, addr = s.recvfrom(300)

    try:
      cmd = cmd.decode().strip()
    except UnicodeDecodeError:
      print(f"warning: UnicodeDecodeError on '{cmd}'")
      continue

    #cmd = input()
    txt.print(f"{cmd}\n")
    print(f"debug: CMD: {cmd}")
    edit.handle_command(cmd)


if __name__ == "__main__":
  main()

#!/usr/bin/python
#
# Copyright 2018 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

__author__      = "Ian Eldred Pudney"

import hashlib
import subprocess
import sys
import threading
import re
import time

def clean_string(string):
  """Removes ANSI escape sequences and non-alphanumeric chars, and converts to lowercase."""
  string = re.sub(r'\x1B\[[0-?]*[ -/]*[@-~]', "", string)

  ret = []
  for c in string:
    if c.isalnum():
      ret.append(c)

  return "".join(ret).lower()

def run_command(command, channel, enable_logging, wait_for="$> "):
  if enable_logging:
    sys.stdout.write(command)
  try:
    channel.stdin.write(command)
  except:
    pass  # avoid broken pipes
  buf = []
  while True:
    c = channel.stdout.read(1)
    if enable_logging:
      sys.stdout.write(c)
    if len(c) == 0:
      break
    buf.append(c)
    if len(buf) >= len(wait_for) and "".join(buf[-len(wait_for):]) == wait_for:
      break
  result = "".join(buf)
  return result

def shash(data):
  return hashlib.sha256(data).hexdigest()

def run_asparagus(path, serial, infile, outfile, enable_logging, expected_outfile=None):
  """Run the ASPARAGUS binary at the specified path, with input.

  Sends input from the specified file to ASPARAGUS, once per line.
  Writes the hash of each line's result to the specified file.
  If enable_logging is true, shows the data transmitted in the
  terminal. Finally, returns the hash of the whole output."""
  process = subprocess.Popen([path], executable=path, stdin=subprocess.PIPE, stdout=subprocess.PIPE)
  outhashes = ""

  result = run_command("", process, enable_logging, wait_for=": ")
  h = shash(clean_string(result))
  outfile.write(h + "\n")
  outhashes += h + "\n"


  if expected_outfile is not None:
    expected_line = expected_outfile.readline()
    if expected_line[-1] == "\n":
      expected_line = expected_line[0:-1]
    if expected_line != shash(h): # double-hashed to prevent reverse-engineering
        print "Got wrong pre-serial output: " + h[0:8] + "/" + shash(h)[0:8] + "/" + expected_line[0:8]
        return

  for line in infile:
    if line[-1] != "\n":
      line = line + "\n"
    line = line.replace("__SERIAL__", serial)
    line = line.replace("__PROGRAM_NAME__", path)
    result = run_command(line, process, enable_logging)
    h = shash(clean_string(result))
    outfile.write(h + "\n")
    outhashes += h + "\n"

    if expected_outfile is not None:
      expected_line = expected_outfile.readline()
      if expected_line[-1] == "\n":
        expected_line = expected_line[0:-1]
      if expected_line != shash(h): # double-hashed to prevent reverse-engineering
        print "Got wrong output for command '" + line[0:-1] + "': "  + h[0:8] + "/" + shash(h)[0:8] + "/" + expected_line[0:8]
        return

    if not result:
      break

  process.wait()

  return shash(outhashes)


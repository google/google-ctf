# Copyright 2025 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import enum
import json
import subprocess
from typing import Literal

import lwe_solver


class Commands(enum.StrEnum):
  CHECK_PATH = "check_path"
  GET_FLAG = "get_flag"


def json_call(
  command: Literal[Commands.CHECK_PATH, Commands.GET_FLAG], data: list[int]
):
  if command == Commands.CHECK_PATH:
    subcommand = "segment"
  elif command == Commands.GET_FLAG:
    subcommand = "lwe_secret_s"

  return json.dumps(
    {
      "command": command,
      subcommand: data,
    }
  )


def load_graph(filepath):
  with open(filepath, "r") as f:
    graph_data = json.load(f)
  return {int(k): v for k, v in graph_data.items()}


def main():
  # startup
  challenge = subprocess.Popen(
    ["python3", "filtermaze_local.py"],
    stdin=subprocess.PIPE,
    stdout=subprocess.PIPE,
    text=True,
  )

  # consume intro
  for _ in range(3):
    l = challenge.stdout.readline()
    print(l)
    if not l:
      break

  graph = load_graph("graph.json")
  curr_path = [0]
  found_mags = False

  while not found_mags:
    neighbors = graph[curr_path[-1]]
    for n in neighbors:
      challenge.stdin.write(f"{json_call(Commands.CHECK_PATH, curr_path + [n])}\n")
      challenge.stdin.flush()
      res = json.loads(challenge.stdout.readline())
      if res["status"] == "valid_prefix":
        curr_path += [n]
      if res["status"] == "path_complete":
        e_mags = res["lwe_error_magnitudes"]
        found_mags = True
        break

  with open("lwe_secret_params.json", "r") as p:
    lwe_params = json.load(p)

  secr = lwe_solver.lwe_solver(
    lwe_params["lwe_n"],
    lwe_params["lwe_m"],
    lwe_params["lwe_q"],
    lwe_params["A"],
    lwe_params["b"],
    e_mags,
  )
  # getflag
  challenge.stdin.write(
    f"{json_call(Commands.GET_FLAG, [int(i) for i in secr.list()])}\n"
  )
  print(f"{json_call(Commands.GET_FLAG, [int(i) for i in secr.list()])}")

  challenge.stdin.flush()

  flag = json.loads(challenge.stdout.readline())
  print(flag)


if __name__ == "__main__":
  main()

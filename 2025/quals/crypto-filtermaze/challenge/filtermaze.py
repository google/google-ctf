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

# filtermaze.py
import json
import secrets
import sys
from dataclasses import asdict, dataclass, field
from typing import List

import numpy as np

with open("/secret_path.json", "r") as sp:
  SECRET_HAMILTONIAN_PATH = json.load(sp).get("SECRET_HAMILTONIAN_PATH")


@dataclass
class LWEParams:
  lwe_n: int = 50
  lwe_m: int = 100
  lwe_q: int = 1009
  A: List[int] = field(init=False)
  s: List[int] = field(init=False)
  e: List[int] = field(init=False)
  b: List[int] = field(init=False)

  def __post_init__(self):
    self.lwe_error_range = [secrets.randbelow(self.lwe_q) for _ in range(self.lwe_m)]


def load_graph(filepath):
  with open(filepath, "r") as f:
    graph_data = json.load(f)
  return {int(k): v for k, v in graph_data.items()}


def load_flag(filepath):
  with open(filepath, "r") as f:
    flag = f.readline().strip()
  return flag


def create_lwe_instance_with_error(n, m, q, error_mags):
  s = np.array([secrets.randbelow(q) for _ in range(n)], dtype=int)
  A = np.random.randint(0, q, size=(m, n), dtype=int)  # Public matrix
  e = np.array([secrets.choice([-mag, +mag]) for mag in error_mags], dtype=int)
  b = (A @ s + e) % q
  return A.tolist(), s.tolist(), e.tolist(), b.tolist()


class PathChecker:
  def __init__(
    self,
    secret_path,
    graph_data,
    lwe_error_mags,
  ):
    self.secret_path = secret_path
    self.graph = graph_data
    self.lwe_error_mags = lwe_error_mags
    self.path_len = len(self.secret_path)

  def check(self, candidate_segment):
    seg_len = len(candidate_segment)
    if seg_len > self.path_len:
      return False
    for i, node in enumerate(candidate_segment):
      if node != self.secret_path[i]:  # Node mismatch
        return False

      if i > 0:
        prev_node = candidate_segment[i - 1]
        neighbors = self.graph.get(prev_node)
        if neighbors is None or node not in neighbors:
          return False

    if seg_len == self.path_len:
      error_magnitudes = [int(abs(err_val)) for err_val in self.lwe_error_mags]
      return error_magnitudes
    else:
      return True


def main():
  flag = load_flag("/flag")
  graph_data = load_graph("graph.json")
  lwe_params = LWEParams()
  if len(sys.argv) > 1:
    if sys.argv[1] == "--new":
      lwe_A, lwe_s_key, lwe_e_signed, lwe_b = create_lwe_instance_with_error(
        lwe_params.lwe_n, lwe_params.lwe_m, lwe_params.lwe_q, lwe_params.lwe_error_range
      )
      lwe_params.A = lwe_A
      lwe_params.b = lwe_b
      lwe_params.s = lwe_s_key
      lwe_params.e = lwe_e_signed
      with open("lwe_secret_params.json", "w") as s:
        json.dump(asdict(lwe_params), s, indent=2)
  else:
    with open("/lwe_secret_params.json", "r") as s:
      lwe_params = json.load(s)
    lwe_A = lwe_params.get("A")
    lwe_s_key = lwe_params.get("s")
    lwe_e_signed = lwe_params.get("e")
    lwe_b = lwe_params.get("b")

  path_checker = PathChecker(
    secret_path=SECRET_HAMILTONIAN_PATH,
    graph_data=graph_data,
    lwe_error_mags=lwe_e_signed,
  )

  initial_messages = [
    "Welcome! I've hidden the key at the end of the maze. You can use this to open the chest to get the flag.",
    'Commands: {"command": "check_path", "segment": [...]}',
    '          {"command": "get_flag", "lwe_secret_s": [...] }',
  ]
  for msg in initial_messages:
    print(msg, flush=True)

  for line in sys.stdin:
    data_str = line.strip()
    if not data_str:
      continue

    response_payload = {}
    try:
      client_command = json.loads(data_str)
      command = client_command.get("command")

      if command == "check_path":
        segment = client_command.get("segment")
        if not isinstance(segment, list):
          raise TypeError("Segment must be a list.")
        path_result = path_checker.check(segment)

        if isinstance(path_result, list):
          response_payload = {
            "status": "path_complete",
            "lwe_error_magnitudes": path_result,
          }
        elif path_result is True:
          response_payload = {"status": "valid_prefix"}
        else:
          response_payload = {"status": "path_incorrect"}
      elif command == "get_flag":
        key_s_raw = client_command.get("lwe_secret_s")
        if not isinstance(key_s_raw, list):
          raise TypeError("lwe_secret_s must be a list.")

        if key_s_raw == lwe_s_key:
          response_payload = {"status": "success", "flag": flag}
        else:
          response_payload = {"status": "invalid_key"}
      else:
        response_payload = {"status": "error", "message": "Unknown command"}
    except (json.JSONDecodeError, ValueError, TypeError) as e:
      json_err = f"Invalid format or data: {e}"
      response_payload = {
        "status": "error",
        "message": json_err,
      }
    except Exception as e_cmd:
      err_mesg = f"Error processing command '{data_str}': {e_cmd}"
      response_payload = {"status": "error", "message": err_mesg}

    print(json.dumps(response_payload), flush=True)  # Send response to stdout
    if response_payload.get("flag"):
      break


if __name__ == "__main__":
  main()

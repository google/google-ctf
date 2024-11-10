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

import gzip
import logging
import os
import sys
import dill
from map import tilemap

sys.path.append(
    os.path.abspath(os.path.join(os.path.dirname(__file__), os.path.pardir))
)


def main(map_file: str, output_file: str):
  logger = logging.getLogger()
  logger.setLevel(logging.DEBUG)

  logging.info(f"Parsing file {map_file}")

  map = tilemap.TileMap(map_file)

  with gzip.GzipFile(output_file, "wb") as f:
    dill.dump(map, f)

  logging.info(f"Dumped mgz map to {output_file} successfully.")


if __name__ == "__main__":
  if len(sys.argv) != 3:
    print(f"Usage: {sys.argv[0]} <map_file.tmx> <output_file.mgz>")
    exit(1)
  main(sys.argv[1], sys.argv[2])

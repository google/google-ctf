#!/usr/bin/python3
# Copyright 2020 Google LLC
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
#
# Helper script for Tiled to export maps in game format (and generate a respawn
# map).
# NOTE: You'll have to change the paths below.
# NOTE: You can add this script to Tiled's commands: path\bundle.py %mapfile
import sys
import json
import os
import subprocess
import base64
import hashlib

TILED = os.environ.get("TILED_EXECUTABLE", "d:\\bin\\Tiled\\tiled.exe")
CONVERT_BINARY = "d:\\commands\\bin\\convert.exe"
KNOWN_PATH_FIELDS = { "image" }

def export_to_json(tmx_full_name, json_full_name):
  print("[   ] Exporting map: %s" % tmx_full_name)
  subprocess.check_call([
    TILED,
    "--export-map",
    "--embed-tilesets",
    tmx_full_name,
    json_full_name
  ])
  print("[ + ] JSON file: %s" % json_full_name)

def bundle_file(bundle_dir, file_full_name):
  with open(file_full_name, "rb") as f:
    d = f.read()

  random_prefix = hashlib.sha256(d).hexdigest()[:10]
  final_name = "%s-%s" % (random_prefix, os.path.basename(file_full_name))
  final_full_name = os.path.join(bundle_dir, final_name)

  with open(final_full_name, "wb") as f:
    f.write(d)

  return final_name

def bundle_worker(top_level_dir, bundle_dir, d, path):
  if type(d) is str:
    if ('/' in d or '\\' in d) and (not path.endswith(".data")):
      print("[wrr] Potential unhandled path in %s: %s" % (path, d))
    return

  if type(d) in { float, int, bool }:
    return

  if type(d) is list:
    for i, e in enumerate(d):
      bundle_worker(top_level_dir, bundle_dir, e, "%s[%i]" % (path, i))
    return

  if type(d) is dict:
    for k, v in d.items():
      if k in KNOWN_PATH_FIELDS and type(v) is str:

        if os.path.isabs(v):
          file_full_name = os.path.realpath(v)
        else:
          file_full_name = os.path.realpath(os.path.join(top_level_dir, v))

        if not os.access(file_full_name, os.R_OK):
          sys.exit("[err] Failed to bundle file %s: %s" % (path, v))

        d[k] = bundle_file(bundle_dir, file_full_name)
        continue

      bundle_worker(top_level_dir, bundle_dir, v, "%s.%s" % (path, k))
    return

  print("[err] Unknown field type %s (%s) - skipping" % (path, type(d)))

def bundle(top_level_dir, bundle_dir, input_full_name, output_full_name):
  print("[   ] Bundling files")
  with open(input_full_name) as f:
    data = json.load(f)

  bundle_worker(top_level_dir, bundle_dir, data, "ROOT")

  with open(output_full_name, "w") as f:
    json.dump(data, f, indent=4, sort_keys=True)
  print("[ + ] Final output: %s" % output_full_name)

def generate_respawn_map(input_full_name, raw_full_name, output_full_name):
  COLORS = [
    [0xFF, 0x00, 0x00],
    [0x00, 0x00, 0x00],
    [0x00, 0x80, 0x00],
    [0x00, 0x00, 0x80],
    [0xFF, 0x00, 0xFF],
    [0xC0, 0xC0, 0xC0],
    [0x80, 0x00, 0x80],
    [0x00, 0x80, 0x80],
    [0xFF, 0xFF, 0x00],
    [0x80, 0x00, 0x00],
    [0xFF, 0xFF, 0xFF],
    [0x00, 0xFF, 0x00],
    [0x00, 0x00, 0xFF],
    [0x00, 0xFF, 0xFF],
    [0x80, 0x80, 0x80],
    [0x80, 0x80, 0x00],
  ]

  print("[   ] Generating respawn map")
  with open(input_full_name) as f:
    data = json.load(f)

  respawns = []

  for layer in data["layers"]:
    if layer["name"] == "metadata":
      for obj in layer["objects"]:
        if obj["type"] == "respawn":
          respawns.append([
            obj["x"], obj["y"]
          ])

  map_width = data["width"]
  map_height = data["height"]
  print("[   ] Map size: %i x %i" % (map_width, map_height))

  sz = map_width * map_height * 4
  print("[   ] Creating %i byte bitmap" % (sz))

  m = bytearray(sz)

  idx = 0
  for j in range(map_height):
    for i in range(map_width):
      min_idx = -1
      min_dist_sq = 4000000000

      for ridx, (rx, ry) in enumerate(respawns):
        dx = rx - (i * 32)
        dy = ry - (j * 32)
        dist_sq = dx * dx + dy * dy

        if dist_sq < min_dist_sq:
          min_dist_sq = dist_sq
          min_idx = ridx

      color = COLORS[min_idx % len(COLORS)]
      m[idx + 0] = color[0]
      m[idx + 1] = color[1]
      m[idx + 2] = color[2]
      m[idx + 3] = 50

      idx += 4

  with open(raw_full_name, "wb") as f:
    f.write(m)

  print("[   ] Converting and resizing")
  sys.stdout.flush()

  try:
    subprocess.check_call([
        CONVERT_BINARY,
        "-size", "%ix%i" % (map_width, map_height),
        "-depth", "8",
        "rgba:%s" % raw_full_name,
        "-scale", "3200%",
        output_full_name
    ])
  except FileNotFoundError:
    print("[***] Need imagick's convert to create the PNG of respawn map")

  print("[ + ] Respawn map: %s" % output_full_name)

def main():
  if len(sys.argv) != 2:
    sys.exit("usage: bundle.py <mapfile.tmx>")

  if not os.access(TILED, os.X_OK):
    sys.exit("error: set TILED_EXECUTABLE env variable to tiled.exe path")

  tmx_full_name = sys.argv[1]
  tmx_name = os.path.basename(tmx_full_name)
  tmx_base_name, _ = os.path.splitext(tmx_name)
  tmx_path = os.path.dirname(tmx_full_name)

  json_full_name = os.path.join(tmx_path, "%s-tmp.json" % tmx_base_name)
  bundle_dir = os.path.realpath(os.path.join(
      tmx_path, "bundle-%s" % tmx_base_name))
  json_final_full_name = os.path.join(bundle_dir, "%s.json" % tmx_base_name)

  os.makedirs(bundle_dir, exist_ok=True)

  export_to_json(tmx_full_name, json_full_name)
  bundle(tmx_path, bundle_dir, json_full_name, json_final_full_name)

  raw_full_name = os.path.join(tmx_path, "%s-respawn-map.raw" % tmx_base_name)
  png_full_name = os.path.join(tmx_path, "%s-respawn-map.png" % tmx_base_name)
  generate_respawn_map(json_full_name, raw_full_name, png_full_name)

if __name__ == "__main__":
  main()


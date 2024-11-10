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

# Converts Tiled .tsx and .tmx files to Hackceler8's custom map format
# (simple json for now, can be changed later to be harder to read).
# Also generates a prerender for each level.
# Usage: python3 generate_maps.py [resources dir path]

import codecs
import json
import sys
import os
import math
import subprocess
import struct
import logging

from pathlib import Path
from xml.etree import ElementTree as ET


TILED_H_FLIP_MASK = 0x80000000
TILED_V_FLIP_MASK = 0x40000000
TILED_DIAG_FLIP_MASK = 0x20000000

H_FLIP_MASK = 0x8000
V_FLIP_MASK = 0x4000
DIAG_FLIP_MASK = 0x2000


def _normalize_tile_id(idx):
    # In Tiled, bit 29 is unused but could be set.
    return (idx & ~(1 << 28))


def _convert_tsx(filename):
    xml = ET.parse(filename)
    attr = xml.getroot().attrib
    tw = int(attr["tilewidth"])
    th = int(attr["tileheight"])
    w = int(attr["columns"])
    h = int(math.ceil(int(attr["tilecount"]) / int(attr["columns"])))

    if w == 1 and h == 1:
        # Skip fake tiles used for static images.
        return
    h8t = Path(filename).with_suffix(".h8t")
    logging.info("Generating %s" % h8t)
    with open(h8t, "wb") as tf:
        for i in [tw, th, w, h]:
            tf.write(struct.pack("<H", i))
        image = ""
        anims = []
        for el in xml.getroot():
            if el.tag == "image":
                if image != "":
                    logging.info("'image' in %s set twice: %s %s" % (filename, image, el.attrib))
                    exit(1)
                image = el.attrib["source"]
            elif el.tag == "tile":
                anim = {}
                for e in el:
                    if e.tag == "properties":
                        for ee in e:
                            if ee.tag == "property":
                                if ee.attrib["name"] == "animation":
                                    anim["name"] = ee.attrib["value"]
                                elif ee.attrib["name"] == "loop":
                                    anim["loop"] = True if ee.attrib.get("value", "false") == "true" else False
                        break
                frames = []
                for e in el:
                    if e.tag == "animation":
                        for ee in e:
                            if ee.tag == "frame":
                                frames.append({"id": int(ee.attrib["tileid"]), "duration": int(ee.attrib["duration"])})
                        break
                anim["frames"] = frames
                anims.append(anim)
        tf.write(str.encode(image) + b'\0')
        tf.write(struct.pack("<H", len(anims)))
        for anim in anims:
            tf.write(str.encode(anim["name"]) + b'\0')
            tf.write(struct.pack("?", anim["loop"]))
            frames = anim["frames"]
            tf.write(struct.pack("<H", len(frames)))
            for frame in frames:
                tf.write(struct.pack("<H", frame["id"]))
                tf.write(struct.pack("<H", frame["duration"]))

def _sc(s: str) -> str:
    return codecs.encode(s, 'rot_13')

def _convert_tmx(filename):
    xml = ET.parse(filename)
    attr = xml.getroot().attrib
    tw = int(attr["tilewidth"])
    th = int(attr["tileheight"])
    w = int(attr["width"])
    h = int(attr["height"])
    tiles = []
    layers = []
    objects = []

    for el in xml.getroot():
        if el.tag == "tileset":
            source = el.attrib["source"]
            # .tsx -> .h8t
            source = source[:-3] + "h8t"
            tiles.append({"file": source, "start": int(el.attrib["firstgid"])})
        elif el.tag == "layer":
            layer = {"name": el.attrib["name"], "visible": False if el.attrib.get("visible", "1") == "0" else True}
            if layer["name"] == "spikes":
                layer["visible"] = False
            ldata = []
            for e in el:
                if e.tag == "data":
                    txt = e.text.strip()
                    if not txt.endswith(","):
                        txt += ","
                    ldata = [[_normalize_tile_id(int(i)) for i in col.split(",")[:-1]] for col in txt.split("\n")]
                    break
            layer["data"] = ldata
            layers.append(layer)
        elif el.tag == "objectgroup":
            for e in el:
                if e.tag == "object":
                    if "name" not in e.attrib:
                        logging.critical("object without a name: %s" % str(e.attrib))
                        exit(1)
                    obj = {"name": e.attrib["name"], "x": float(e.attrib["x"]), "y": float(e.attrib["y"])}
                    if "width" in e.attrib:
                        obj["w"] = float(e.attrib["width"])
                        obj["h"] = float(e.attrib["height"])
                    objects.append(obj)
                    for ee in e:
                        if ee.tag == "properties":
                            for p in ee:
                                if p.tag == "property":
                                    v = p.attrib["value"]
                                    if "type" in p.attrib:
                                        if p.attrib["type"] == "bool":
                                            v = (v == "true")
                                        elif p.attrib["type"] == "int":
                                            v = int(v)
                                        elif p.attrib["type"] == "float":
                                            v = float(v)
                                    obj[p.attrib["name"]] = v

    if len(layers) == 1 and len(layers[0]["data"]) == 1:
        # Skip fake maps used for sprites.
        return

    h9m = Path(filename).with_suffix(".h9m")
    logging.info("Generating %s" % h9m)
    j = {_sc("tw"): tw, _sc("th"): th, _sc("w"): w, _sc("h"): h}
    j[_sc("tiles")] = []
    for tile in tiles:
        j[_sc("tiles")].append({_sc("file"): _sc(tile["file"]), _sc("start"): tile["start"]})
    j[_sc("layers")] = []
    for layer in layers:
        h = len(layer["data"])
        w = max([len(i) for i in layer["data"]])
        l = {_sc("name"): _sc(layer["name"]), _sc("w"): w, _sc("h"): h, _sc("visible"): layer["visible"]}
        ds = []
        for y in range(h):
            for x in range(w):
                if x >= len(layer["data"][y]):
                    logging.critical("Insufficient row length:", w, ">", len(layer["data"][y]))
                    exit(0)
                d = layer["data"][y][x]
                hf = (d & TILED_H_FLIP_MASK) > 0
                vf = (d & TILED_V_FLIP_MASK) > 0
                df = (d & TILED_DIAG_FLIP_MASK) > 0
                d = d & ~(TILED_H_FLIP_MASK + TILED_V_FLIP_MASK + TILED_DIAG_FLIP_MASK)
                for f, mask in [(hf, H_FLIP_MASK), (vf, V_FLIP_MASK), (df, DIAG_FLIP_MASK)]:
                    if f:
                        d |= mask
                ds.append(d)
        l[_sc("data")] = ds
        j[_sc("layers")].append(l)
    j[_sc("objects")] = []
    for obj in objects:
        o = {}
        for k, v in obj.items():
            o[_sc(k)] = _sc(v) if isinstance(v, str) else v
        j[_sc("objects")].append(o)


    with open(h9m, "w") as mf:
        mf.write(json.dumps(j))


    logging.info("Generating prerender for %s" % filename)
    _generate_prerender(filename)


def _generate_prerender(map_filename):
    filename = map_filename[:-4] + "_prerender.png"
    for tiled_binary in ["tiled", "Tiled", os.path.join(Path.home(), "tiled"), os.path.join(Path.home(), "Tiled")]:
        args = [tiled_binary, "tmxrasterizer", map_filename, filename, "--hide-object-layers"]
        try:
            p = subprocess.run(args, capture_output=True)
            if b"--hide-object-layers" in p.stderr:
                # Older version of Tiled.
                args = ["tmxrasterizer", map_filename, filename, "--hide-layer", "objects", "--hide-layer", "player", "--hide-layer", "Interactions", "--hide-layer", "walls"]
                p = subprocess.run(args, capture_output=True)
            if len(p.stdout) != 0:
                logging.info("Tiled info: " + str(p.stdout))
            if len(p.stderr) != 0:
                logging.critical("Tiled error: " + str(p.stderr))
        except Exception as e:
            logging.critical(e)
            continue
        return

    # MacOS
    args = ["/Applications/Tiled 2.app/Contents/MacOS/tmxrasterizer", map_filename, filename, "--hide-object-layers"]
    try:
        p = subprocess.run(args)
        return
    except Exception as e:
        logging.critical(f"Error running Tiled: {e} (check if Tiled binary exists?)")


def _is_up_to_date(path):
    if path.endswith(".tsx"):
        gen = Path(path).with_suffix(".h8t")
    elif path.endswith(".tmx"):
        gen = Path(path).with_suffix(".h9m")
    else:
        logging.critical("Unknown path extension %s" % path)
        exit(1)
    try:
        orig_time = os.path.getmtime(path)
        gen_time = os.path.getmtime(gen)
    except Exception as e:
        logging.critical(e)
        return False
    return gen_time >= orig_time


def _generate(path, check_timestamp):
    if path.endswith(".tsx"):
        if not check_timestamp or not _is_up_to_date(path):
            _convert_tsx(path)
    elif path.endswith(".tmx"):
        if not check_timestamp or not _is_up_to_date(path):
            _convert_tmx(path)


def generate(path):
    if os.path.isfile(path):
        _generate(path, check_timestamp=False)
        return
    # Go through the directory
    for root, dirs, files in os.walk(path, topdown=True):
        for f in files:
            path = os.path.join(root, f)
            _generate(path, check_timestamp=True)


if __name__ == "__main__":
    input_path = "../resources" if len(sys.argv) < 2 else sys.argv[1]
    generate(input_path)

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

from collections import defaultdict
import gzip
import json
import logging
import os
from pathlib import Path
import struct
import uuid
from typing import Optional

import dill
from game.components.boss.dialogue_boss import DialogueBoss
from game.components.boss.fighting_boss import FightingBoss
from game.components import arcade_box
from game.components import boss_gate
from game.components import env_element
from game.components import fire
from game.components import items
from game.components import key_gate
from game.components import ouch
from game.components import player
from game.components import portal
from game.components import wall
from game.components import warp
from game.components import piquackso
from game.components.enemy import enemy_types
from game.components.npc import npc_types
from game.components.weapon.weapon import Weapon
from game.engine import hitbox
from game.engine.generics import GenericObject
from game.engine.point import Point
from game.engine import gfx
from game.map.tileset import Tileset, read_str
from game.components.stateful import Crops
import xxhash


class _Size:
    def __init__(self, w: int, h: int):
        self.width = w
        self.height = h

    def __repr__(self):
        return "[%d x %d]" % (self.width, self.height)

class Coin:
    def __init__(self, lvl: str, x, y: int, id: str):
        self.lvl = lvl
        self.x = x
        self.y = y
        self.id = id

def init_coins():
    return []

class TileMap:
    H_FLIP_MASK = 0x8000
    V_FLIP_MASK = 0x4000
    DIAG_FLIP_MASK = 0x2000
    coins = init_coins()

    def __init__(self, map_file: str):
        self.file_path = map_file
        self.objects: list[GenericObject] = []
        self.weapons: list[Weapon] = []
        self.env_tiles: list[env_element.EnvElement] = []
        self.size: Optional[_Size] = None
        self.tile_size: Optional[_Size] = None
        self.map_size_pixels: Optional[_Size] = None
        self.arcade_scene: Optional[gfx.TileMap] = None
        self.stateful_objects = []

        self.parse(map_file)

        logging.debug(self.map_size_pixels)
        logging.debug(f"Have a total of {len(self.objects)} objects")

        logging.debug(f"Parsed map {map_file}")

    def parse_layers(self, mf):
        for i in range(struct.unpack("<H", mf.read(2))[0]):
            self.parse_layer(mf)

        for i in range(struct.unpack("<H", mf.read(2))[0]):
            self.parse_object(mf, self.size.height * 16)

    def parse_layer(self, mf):
        name = read_str(mf)
        h = struct.unpack("<H", mf.read(2))[0]
        w = struct.unpack("<H", mf.read(2))[0]
        _visible = struct.unpack("?", mf.read(1))[0]
        if name == "platforms":
            self.parse_platform_layer(mf, h, w)
        elif name.endswith("_env"):
            self.parse_env_layer(mf, h, w, name.removesuffix("_env"))
        else:  # Skip layer
            mf.seek(2 * h * w, 1)

    def parse_platform_layer(self, mf, h, w):
        # we assume that only walls / static colliding elements are in the platform
        # layer
        max_y = h * 16
        rects = []

        for row in range(h):
            for column in range(w):
                if struct.unpack("<H", mf.read(2))[0] != 0:
                    coords = Point(column * 16, max_y - row * 16)
                    x_0, y_0 = column * 16, max_y - row * 16
                    rects.append(hitbox.Hitbox(x_0, x_0 + 16, y_0 - 16, y_0))
        logging.debug(f"Have a total of {len(rects)} elements")
        hc = hitbox.HitboxCollection(rects)
        hc.combine_y()
        hc.combine_x()
        res = hc.dump_rects()
        logging.debug(f"Have a total of {len(res)} objects")
        for i in res:
            w = wall.Wall(coords, i.x1, i.x2, i.y1, i.y2, "generic_platform")
            self.objects.append(w)

    def parse_env_layer(self, mf, h, w, env):
        # we assume that only modifiying elements are in this layer
        max_y = h * 16

        rects = defaultdict(list)

        for row in range(h):
            for column in range(w):
                tt = struct.unpack("<H", mf.read(2))[0]
                if tt == 0:
                    continue
                coords = Point(column * 16, max_y - row * 16)
                x_0, y_0 = column * 16, max_y - row * 16
                rects[env].append(
                    hitbox.Hitbox(x_0, x_0 + 16, y_0 - 16, y_0)
                )
        for pt in rects:
            logging.debug(f"Parsing {pt} tiles")
            tmp_p = rects[pt]
            logging.debug(f"Have a total of {len(tmp_p)} elements")
            hc = hitbox.HitboxCollection(tmp_p)
            hc.combine_y()
            hc.combine_x()
            res = hc.dump_rects()
            logging.debug(f"Have a total of {len(res)} objects")
            for i in res:
                self.env_tiles.append(
                    env_element.EnvElement(
                        coords, i.x1, i.x2, i.y1, i.y2,
                        f"env_{pt}",
                        modifier=pt,
                    )
                )

    def parse_object(self, mf, max_y):
        o = {}
        for i in range(struct.unpack("<H", mf.read(2))[0]):
            key = read_str(mf)
            match mf.read(1):
                case b'\x00':
                    val = read_str(mf)
                case b'\x01':
                    val = struct.unpack("?", mf.read(1))[0]
                case b'\x02':
                    val = struct.unpack("<i", mf.read(4))[0]
                case b'\x03':
                    val = struct.unpack("<f", mf.read(4))[0]
                case _:
                    logging.error(f"Invalid val type")
                    return
            o[key] = val
        name = o["name"]
        coords = Point(o["x"], max_y - o["y"])
        logging.debug(coords)
        logging.debug(
            f"Parsing object of type {name} with properties {o} placed at"
            f" {coords}"
        )
        # coords will be used from here on instead
        del o['x']
        del o['y']
        if name == "fire":
            if "min_distance" in o:
                self.objects.append(fire.Fire(coords, min_distance=o["min_distance"]))
            else:
                logging.warning("No min_distance set")

        elif name == "ouch" or name == "spike_ouch":
            md = o.get("min_distance", 16)
            dmg = o.get("damage", 1)
            cls = ouch.Ouch if name == "ouch" else ouch.SpikeOuch
            self.objects.append(cls(coords, _Size(o["w"], o["h"]), min_distance=md, damage=dmg))
            logging.debug("added new ouch object")

        elif name == "arcade_box":
            self.objects.append(arcade_box.ArcadeBox(coords))

        elif name.endswith("_npc"):
            self.objects.append(npc_types.NPC_TYPES[name](coords=coords, **o))

        elif name.endswith("_enemy"):
            self.objects.append(
                enemy_types.ENEMY_TYPES[name](
                    coords=coords,
                    **o
                )
            )

        elif name == "boss":
            bType = o["type"]
            match bType:
                case "dialogue":
                    boss = DialogueBoss(coords)
                case "fighting":
                    boss = FightingBoss(coords)
                case _:
                    logging.error(f"Invalid boss type {bType}")
                    return
            self.objects.append(boss)

        elif name == "wall":
            logging.debug(o)
            logging.debug("parsing new wall object")
            self.objects.append(wall.Wall(
                coords, coords.x, coords.x + o["w"],
                                  coords.y - o["h"], coords.y, name))
        elif name.endswith("_warp"):
            self.objects.append(warp.Warp(coords, name))
        elif name.endswith("_boss_gate"):
            self.objects.append(boss_gate.BossGate(coords, name, o["stars_needed"]))
        elif name.startswith("key_gate"):
            self.objects.append(key_gate.KeyGate(coords, name))

        elif name.startswith("item_"):
            name = name[len("item_"):]
            logging.debug(o)
            logging.debug("parsing new item object")
            self.objects.append(
                items.Item(
                    coords,
                    name,
                    o.get("display_name"),
                )
            )

        elif name == "portal":
            logging.debug(o)
            logging.debug("parsing new portal object")
            dest = Point(o["dest_x"], max_y - o["dest_y"])
            # Keep the speed if None
            x_speed = o.get("x_speed", None)
            y_speed = o.get("y_speed", None)
            usage_limit = o.get("usage_limit", None)
            visible = o.get("visible", True)
            self.objects.append(
                portal.Portal(
                    coords,
                    _Size(o["w"], o["h"]),
                    name,
                    dest,
                    x_speed=x_speed,
                    y_speed=y_speed,
                    usage_limit=usage_limit,
                    visible=visible,
                )
            )

        elif name == "player":
            p = player.Player(coords)
            self.objects.append(p)
            logging.debug(
                f"Added new player at {coords}"
            )

        elif name == "weapon":
            o["coords"] = coords
            self.weapons.append(o)

        elif name.startswith("stateful_"):
            match name.split("stateful_")[1]:
                case "crops":
                    c = Crops(coords=coords)
                    self.objects.append(c)
                    logging.info("Got some crops")
            logging.info("Got a new stateful object")

        elif name == "piquackso":
            o = piquackso.Piquackso(coords)
            self.objects.append(o)
        else:
            logging.critical(f"Unknown object: {name}")

    def parse_coins(self):
        for c in self.coins:
            if c.lvl in self.file_path:
                self.objects.append(
                    items.Item(
                    Point(c.x, c.y),
                    "coin_"+c.id,
                    "Coin",
                )
            )

    def parse(self, map_file):
        logging.debug(f"Parsing file {map_file}")
        with open(map_file, "rb") as mf:
            self.tile_size = _Size(
                struct.unpack("<H", mf.read(2))[0],
                struct.unpack("<H", mf.read(2))[0],
            )
            self.size = _Size(
                struct.unpack("<H", mf.read(2))[0],
                struct.unpack("<H", mf.read(2))[0],
            )
            self.map_size_pixels = _Size(
                self.size.width * self.tile_size.width,
                self.size.height * self.tile_size.height)

            # Skip tiles
            for i in range(struct.unpack("<H", mf.read(2))[0]):
                _ = read_str(mf)
                mf.seek(2, 1)

            self.parse_layers(mf)
            self.parse_coins()

    def get_arcade_scene(self) -> gfx.TileMap:
        if self.arcade_scene is not None:
            return self.arcade_scene

        cwd = os.path.dirname(os.path.realpath(self.file_path))

        scene = gfx.TileMap()
        starts = []
        with open(self.file_path, "rb") as mf:
            # Skip ahead to tiles
            mf.seek(8, 0)
            for i in range(struct.unpack("<H", mf.read(2))[0]):
                ts_path = os.path.join(cwd, read_str(mf))
                start = struct.unpack("<H", mf.read(2))[0]
                tileset = Tileset()
                tileset.load(ts_path)
                starts.append((start, tileset, os.path.dirname(ts_path)))
            # Layers
            for i in range(struct.unpack("<H", mf.read(2))[0]):
                name = read_str(mf)
                h = struct.unpack("<H", mf.read(2))[0]
                w = struct.unpack("<H", mf.read(2))[0]
                visible = struct.unpack("?", mf.read(1))[0]

                max_y = h * 16
                for row in range(h):
                    for column in range(w):
                        idx = struct.unpack("<H", mf.read(2))[0]
                        if not visible or idx == 0:
                            continue

                        h_flip = ((idx & TileMap.H_FLIP_MASK) != 0)
                        idx &= ~TileMap.H_FLIP_MASK
                        v_flip = ((idx & TileMap.V_FLIP_MASK) != 0)
                        idx &= ~TileMap.V_FLIP_MASK
                        diag_flip = ((idx & TileMap.DIAG_FLIP_MASK) != 0)
                        idx &= ~TileMap.DIAG_FLIP_MASK

                        coords = Point(column * 16, max_y - row * 16)
                        for s in starts:
                            if idx < s[0]:
                                break
                            start, tileset, ts_path = s

                        if idx - start > tileset.w * tileset.h:
                            logging.error(f"tile with ID {idx} larger than max ID in {ts_path} [start {start}, w {tileset.w}, h {tileset.h}]")
                            logging.info(f"tileset {tileset} {tileset.image}")
                            exit(1)
                        idx -= start

                        offs_x = (idx % tileset.w) * tileset.tw
                        offs_y = (tileset.h * tileset.th) - (1 + (idx // tileset.w)) * tileset.th

                        ts_dir = ts_path
                        texture = gfx.load_image(
                            os.path.join(ts_dir, tileset.image),
                            x=offs_x, y=offs_y, w=tileset.tw, h=tileset.th,
                            flip_h=h_flip,
                            flip_v=v_flip,
                            flip_diag=diag_flip,
                        )
                        scene.add_sprite(name, x=coords.x + tileset.tw * 0.5, y=coords.y - tileset.th * 0.5, img=texture)

        scene.build()
        self.arcade_scene = scene
        return self.arcade_scene

    @staticmethod
    def transform_position(pos_tiled: tuple, max_x: int):
        x = pos_tiled[0]
        y = pos_tiled[1]
        return max_x - x, y

    @staticmethod
    def from_mgz(path: str):
        logging.debug(f"Loading mgz map from {path}")
        with gzip.GzipFile(path, "rb") as f:
            return dill.load(f)

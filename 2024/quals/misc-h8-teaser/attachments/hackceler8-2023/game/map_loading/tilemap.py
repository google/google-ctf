# Copyright 2023 Google LLC
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
from pathlib import Path
import logging
import uuid
import dill
import gzip

import arcade
import pytiled_parser
import xxhash

from components import arena
from components import boss
from components import boss_gate
from components import door
from components import env_element
from components import exitarea
from components import fire
from components import flag
from components import logic
from components import magic_items
from components import moving_platform
from components import ouch
from components import player
from components import portal
from components import speed_tile
from components import spike
from components import switch
from components import wall
from components import weapon
from components.enemy import enemy_types
from components.npc import npc_types
from engine import hitbox
from engine.quadtree import Quadtree, Bounds


def image_tileset_to_texture(tileset: pytiled_parser.tileset, k: int) -> list[
    pytiled_parser.Tile]:
    logging.debug(
        f"Parsing set with {tileset.tile_count} tiles ({tileset.tile_width} x {tileset.tile_height}), {tileset.columns} columns")
    res_dict = defaultdict(arcade.Texture)

    g = arcade.load_spritesheet(
        file_name=tileset.image,
        sprite_width=tileset.tile_width,
        sprite_height=tileset.tile_height,
        columns=tileset.columns,
        count=tileset.tile_count
    )
    for (i, val) in enumerate(g):
        res_dict[k + i] = val
    return res_dict


def parse_tileset(tileset: pytiled_parser.tileset, k: int):
    return image_tileset_to_texture(tileset, k)


class BasicTileMap:
    def __init__(self, map_file):
        self.parsed_map = None
        self.texts = None
        self.layers = []
        self.objs = []
        self.dynamic_artifacts = []
        self.weapons = []
        self.env_tiles = []
        self.player_bounds_id = None
        self.obj_map = {}
        self.logic_map = {}

        self.static_objs = []
        self.moving_platforms = []

        self.map_file = map_file
        self.parse_and_print()

        self.map_size = self.parsed_map

        self.parse_layers()
        self.size = self.get_size()
        self.tile_size = self.parsed_map.tile_size
        self.map_size_pixels = self.get_size_pixel()

        self.width_pixel = self.size[0] * self.tile_size[0]
        self.height_pixel = self.size[1] * self.tile_size[0]

        logging.debug(self.width_pixel)
        logging.debug(self.height_pixel)

        self.qt = Quadtree(Bounds(0, self.size[1] * self.tile_size[0], self.size[0] *
                                  self.tile_size[0], self.size[1] * self.tile_size[0],
                                  str(uuid.uuid4())),
                           256)
        for o in self.objs:
            if o.bounds.idi == self.player_bounds_id:
                continue
            logging.debug(f"Inserting object {o.bounds.dump()} into tree")
            t = self.qt.insert(o.bounds)
            if not t:
                logging.error("Failed to insert object")
            self.obj_map[o.unique_id] = o

        logging.debug(self.map_size_pixels)
        logging.debug(f"Have a total of {len(self.objs)} objects")

        logging.debug(f"Parsed map {self.map_file}")

        self.done = False

    def hck_hash(self):
        h = ""
        for i in self.static_objs + self.objs + self.dynamic_artifacts:
            try:
                h += i.hash
            except Exception as e:
                logging.critical(f"Failed to dump hash: {str(e)}")
        return xxhash.xxh64(h.encode()).hexdigest()

    def parse_layers(self):
        obj_layers = []
        max_y = 0
        for k in self.parsed_map.layers:
            if not isinstance(k, pytiled_parser.TileLayer):
                obj_layers.append(k)
            else:
                max_y = max(max_y, k.size[1])
                if k.name == "platforms":
                    self.parse_platform_layer(k)
                    continue
                if k.name == "spikes":
                    self.parse_spike_layer(k)
                    continue
                if k.name == "item":
                    self.parse_item_layer(k)
                    continue
                if k.name == "elements":
                    self.parse_env_layer(k)
                    continue

                self.layers.append(k)

        logging.debug(f"Map height: {max_y * 16}")
        for k in obj_layers:
            for o in k.tiled_objects:
                self.parse_object(o, max_y * 16)

    def parse_platform_layer(self, layer):
        # we assume that only walls / static colliding elements are in the platform
        # layer
        logging.debug(layer.size)

        class _Size:
            def __init__(self, w, h):
                self.width = w
                self.height = h

        max_y = len(layer.data) * 16
        logging.debug(max_y)

        polys = []

        for row in range(len(layer.data)):
            for column in range(len(layer.data[row])):
                if layer.data[row][column] != 0:
                    coords = pytiled_parser.OrderedPair(column * 16,
                                                        max_y - row * 16)
                    x_0, y_0 = column * 16, max_y - row * 16
                    polys.append(hitbox.Hitbox([
                        hitbox.Point(x_0, y_0),
                        hitbox.Point(x_0 + 16, y_0),
                        hitbox.Point(x_0 + 16, y_0 - 16),
                        hitbox.Point(x_0, y_0 - 16),
                    ]))
        logging.debug(f"Have a total of {len(polys)} elements")
        hc = hitbox.HitboxCollection(polys)
        hc.combine_y()
        hc.combine_x()
        res = hc.dump_polys()
        logging.debug(f"Have a total of {len(res)} objects")
        for i in res:
            w = wall.Wall(coords, _Size(16, 16), "generic_platform",
                          perimeter=i.outline)
            self.static_objs.append(w)

    def parse_env_layer(self, layer):
        # we assume that only modifiying element (space, water) are in this layer
        logging.debug(layer.size)
        logging.debug(layer.properties)

        class _Size:
            def __init__(self, w, h):
                self.width = w
                self.height = h

        max_y = len(layer.data) * 16
        logging.debug(max_y)

        polys = defaultdict(list)

        for row in range(len(layer.data)):
            for column in range(len(layer.data[row])):
                tt = layer.data[row][column]
                if tt == 0:
                    continue
                if str(tt) not in layer.properties:
                    logging.debug(f"Ignoring unmapped tile {tt}")
                    continue
                modifier = layer.properties[str(tt)]
                if layer.data[row][column] != 0:
                    coords = pytiled_parser.OrderedPair(column * 16,
                                                        max_y - row * 16)
                    x_0, y_0 = column * 16, max_y - row * 16

                    polys[modifier].append(hitbox.Hitbox([
                        hitbox.Point(x_0, y_0),
                        hitbox.Point(x_0 + 16, y_0),
                        hitbox.Point(x_0 + 16, y_0 - 16),
                        hitbox.Point(x_0, y_0 - 16),
                    ]))
        for pt in polys:
            logging.debug(f"Parsing {pt} tiles")
            tmp_p = polys[pt]
            logging.debug(f"Have a total of {len(tmp_p)} elements")
            hc = hitbox.HitboxCollection(tmp_p)
            hc.combine_y()
            res = hc.dump_polys()
            logging.debug(f"Have a total of {len(res)} objects")
            for i in res:
                self.env_tiles.append(
                    env_element.EnvElement(
                        coords,
                        _Size(16, 16),
                        f"env_{pt}",
                        perimeter=i.outline,
                        modifier=pt
                    ))

    def parse_spike_layer(self, layer):
        max_y = len(layer.data) * 16
        for row in range(len(layer.data)):
            for column in range(len(layer.data[row])):
                if layer.data[row][column] == 0:
                    continue
                coords = pytiled_parser.OrderedPair(column * 16 + 32,
                                                    max_y - row * 16 + 16)
                rng = layer.properties.get("rng")
                rng_type = layer.properties.get("rng_type", 'prng')
                self.objs.append(spike.Spike(coords, rng, rng_type))

    def parse_item_layer(self, layer):
        class _Size:
            def __init__(self, w, h):
                self.width = w
                self.height = h

        max_y = len(layer.data) * 16
        logging.debug(max_y)

        for row in range(len(layer.data)):
            for column in range(len(layer.data[row])):
                if layer.data[row][column] != 0:
                    coords = pytiled_parser.OrderedPair(column * 16 + 8,
                                                        max_y - row * 16 - 8)
                    self.objs.append(
                        magic_items.Item(coords, layer.properties.get("item_name"),
                                         layer.properties.get("display_name"),
                                         layer.properties.get("color")))


    def parse_object(self, o, max_y):
        name = o.name
        props = o.properties
        logging.debug(o.coordinates)
        coords = pytiled_parser.OrderedPair(o.coordinates.x, max_y - o.coordinates.y)
        logging.debug(
            f"Parsing object of type {name} with properties {props} placed at {coords}")
        if o.name == "Fire":
            if "min_distance" in props:
                self.dynamic_artifacts.append(
                    fire.Fire(coords, min_distance=props["min_distance"]))
            else:
                logging.warning("No min_distance set")

        elif o.name == "ouch" or o.name == "spike_ouch":
            md = props.get("min_distance", 16)
            dmg = props.get("damage", 1)
            cls = ouch.Ouch if o.name == "ouch" else ouch.SpikeOuch
            self.dynamic_artifacts.append(cls(coords, o.size, min_distance=md,
                                              damage=dmg))
            logging.debug("added new ouch object")

        elif o.name == "switch":
            self.objs.append(switch.Switch(coords))

        elif "npc" in o.name:
            walk_data = o.properties.get("walk_data", "")
            logging.debug(f"{o.name} || {coords} || {walk_data}")
            self.objs.append(npc_types.NPC_TYPES[o.name](coords, o.name, walk_data))

        elif "enemy" in o.name:
            self.objs.append(enemy_types.ENEMY_TYPES[o.name](coords, o.name,
                                                             props.get("damage", None),
                                                             props.get("respawn",
                                                                       False),
                                                             props.get("respawn_tick",
                                                                       None),
                                                             props.get("walk_data", ""),
                                                             props.get(
                                                                 "control_inverter",
                                                                 False)))

        elif o.name == "boss":
            version = o.properties["version"]
            self.objs.append(boss.Boss(coords, o.name, version))

        elif "zone" in o.name or "perimeter" in o.name or "solid" in o.name:
            logging.debug(o)
            logging.debug("parsing new wall object")
            self.static_objs.append(wall.Wall(coords, o.size, o.name))
        elif "arena" in o.name:
            logging.debug(o)
            logging.debug("parsing new arena object")
            self.static_objs.append(arena.Arena(coords, o.size, o.name))

        elif o.name.startswith("moving_platform_"):
            p = moving_platform.MovingPlatform(
                coords, o.name, props.get("x_speed", 0.0), props.get("y_speed", 0.0),
                props.get("min_dx", -20), props.get("max_dx", 20),
                props.get("min_dy", -20),
                props.get("max_dy", 20))
            self.moving_platforms.append(p)

        elif o.name.startswith("key_"):
            logging.debug(o)
            logging.debug("parsing new key item object")
            self.objs.append(magic_items.Item(coords, o.name, props.get("display_name"),
                                              props.get("color")))

        elif o.name.startswith("item_"):
            o.name = o.name[len("item_"):]
            logging.debug(o)
            logging.debug("parsing new item object")
            self.objs.append(magic_items.Item(coords, o.name, props.get("display_name"),
                                              wearable=props.get("wearable", False)))
        elif "door" in o.name:
            logging.debug(o)
            logging.debug("parsing new door object")
            self.objs.append(door.Door(coords, o.name))

        elif "exit" in o.name:
            logging.debug(o)
            logging.debug("parsing new exit area object")
            self.static_objs.append(exitarea.ExitArea(coords, o.size, o.name))

        elif "flag" in o.name:
            logging.debug(o)
            logging.debug("parsing new flag object")
            self.objs.append(flag.Flag(coords, o.name))

        elif "portal" in o.name:
            logging.debug(o)
            logging.debug("parsing new portal object")
            dest = hitbox.Point(props["dest_x"], max_y - props["dest_y"])
            # Keep the speed if None
            x_speed = props.get("x_speed", None)
            y_speed = props.get("y_speed", None)
            usage_limit = props.get("usage_limit", None)
            self.static_objs.append(portal.Portal(coords, o.size, o.name, dest,
                                                  x_speed=x_speed,
                                                  y_speed=y_speed,
                                                  usage_limit=usage_limit))

        elif "boss_gate" in o.name:
            self.objs.append(boss_gate.BossGate(coords, o.name))

        elif o.name == "Player":
            hh = props.get("hitbox_height", 32)
            hw = props.get("hitbox_width", 32)

            outline = [
                hitbox.Point(coords.x - hw // 2, coords.y + hh // 2),
                hitbox.Point(coords.x + hw // 2, coords.y + hh // 2),
                hitbox.Point(coords.x + hw // 2, coords.y - hh // 2),
                hitbox.Point(coords.x - hw // 2, coords.y - hh // 2),
            ]

            p = player.Player(coords, outline=outline)
            self.objs.append(p)
            self.player_bounds_id = p.unique_id
            logging.debug(f"Added new player with id: {self.player_bounds_id} at "
                          f"{coords}")

        elif o.name == "speed_tile":
            self.objs.append(speed_tile.SpeedTile(coords, o.name))
        elif o.name == "Weapon":
            logging.debug("Adding weapon")
            logging.debug(o.properties)
            w = weapon.parse_weapon(o.properties, coords)
            if w is not None:
                self.weapons.append(w)
                logging.debug(f"Added new object of type {w.nametype}")

        elif o.name == "Logic":
            logging.debug("Adding logic")
            logging.debug(o)
            logging.debug(o.properties)
            l = logic.parse_logic(o.properties, coords, self.logic_map, getattr(o, "points", None))
            if l is not None:
                self.logic_map[l.logic_id] = l
                if not isinstance(l, logic.PassiveLogicComponent):
                    self.objs.append(l)
                logging.debug(f"Added new logic object of type {l.nametype}")

    def get_size(self):
        w = []
        h = []
        for i in self.layers:
            w.append(i.size.width)
            h.append(i.size.height)
        if len(set(w)) != 1:
            logging.error(f"Multiple layer widths: {set(w)}")
        if len(set(h)) != 1:
            logging.error(f"Multiple layer heights: {set(h)}")

        return w[0], h[0]

    def get_size_pixel(self):
        w, h = self.get_size()
        return w * self.tile_size.width, h * self.tile_size.height

    def parse_and_print(self):
        logging.debug(f"Parsing file {self.map_file}")
        self.parsed_map = pytiled_parser.parse_map(Path(self.map_file))
        logging.debug(self.parsed_map)
        texts = {}

        for k in self.parsed_map.tilesets:
            texts.update(parse_tileset(self.parsed_map.tilesets[k], k))
        logging.debug(f"Parsed {len(texts)} textures")
        self.texts = texts
        logging.debug(self.texts)

    def to_arcade_tilemap(self):
        return arcade.TileMap(tiled_map=self.parsed_map)

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

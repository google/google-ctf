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

import arcade
import pytiled_parser
import xxhash

from components import arena
from components import door
from components import env_element
from components import exitarea
from components import fire
from components import magic_items
from components import moving_platform
from components import npc
from components import ouch
from components import player
from components import wall
from components import weapon
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
                if k.name == "mps":
                    self.parse_platform_layer(k, moving=True)
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

    def parse_platform_layer(self, layer, moving=False):
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
            if moving:
                w = moving_platform.MovingPlatform(coords, _Size(16, 16),
                                               "generic_moving_platform",
                              perimeter=i.outline)

                self.moving_platforms.append(w)
            else:
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
                    coords = pytiled_parser.OrderedPair(column * 16,
                                                        max_y - row * 16)
                    self.objs.append(
                        magic_items.Item(coords, layer.properties.get("item_name"),
                                         layer.properties.get("display_name"),
                                         layer.properties.get("color")))
                    logging.debug(f"Added new object of type "
                                  f"{layer.properties['item_name']}")

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

        elif o.name == "ouch":
            md = props.get("min_distance", 16)
            dmg = props.get("damage", 1)
            self.dynamic_artifacts.append(ouch.Ouch(coords, o.size, min_distance=md,
                                                    damage=dmg))
            logging.debug("added new ouch object")

        elif "npc" in o.name:
            walk_data = o.properties["walk_data"] if "walk_data" in o.properties else ""
            self.objs.append(npc.NPC_TYPES[o.name](coords, o.name, walk_data))

        elif "zone" in o.name or "perimeter" in o.name or "solid" in o.name:
            logging.debug(o)
            logging.debug("parsing new wall object")
            self.static_objs.append(wall.Wall(coords, o.size, o.name))
        elif "arena" in o.name:
            logging.debug(o)
            logging.debug("parsing new arena object")
            self.static_objs.append(arena.Arena(coords, o.size, o.name))

        elif "key" in o.name:
            logging.debug(o)
            logging.debug("parsing new item object")
            self.objs.append(magic_items.Item(coords, o.name, props.get("display_name"), props.get("color")))

        elif "door" in o.name:
            logging.debug(o)
            logging.debug("parsing new door object")
            self.objs.append(door.Door(coords, o.size, o.name, props["unlocker"]))

        elif "exit" in o.name:
            logging.debug(o)
            logging.debug("parsing new exit area object")
            self.static_objs.append(exitarea.ExitArea(coords, o.size, o.name))

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

        elif o.name == "Weapon":
            logging.info("Adding weapon")
            logging.info(o.properties)
            w = weapon.parse_weapon(o.properties, coords)
            if w is not None:
                self.weapons.append(w)
                logging.info(f"Added new object of type {w.nametype}")

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

        return (w[0], h[0])

    def get_size_pixel(self):
        w = []
        h = []
        for i in self.layers:
            w.append(i.size.width)
            h.append(i.size.height)
        if len(set(w)) != 1:
            logging.error(f"Multiple layer widths: {set(w)}")
        if len(set(h)) != 1:
            logging.error(f"Multiple layer heights: {set(h)}")

        return (w[0] * self.tile_size.width, h[0] * self.tile_size.height)

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

    @staticmethod
    def transform_position(pos_tiled: tuple, max_x: int):
        x = pos_tiled[0]
        y = pos_tiled[1]
        return (max_x - x, y)

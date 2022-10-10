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

import pytiled_parser
import pathlib
import environ
import gametree
import serialize
from gametree import Component, Entity, Transform, Vector2f, Vector2
from serialize import Unserialized
import bisect
import math
import game as game_mod
import collision
import utils
import sprites
import spatial_hash
import renderer
from typing import Union, Optional, Dict, Tuple, List, Iterable
import os
import re
import sys

if not hasattr(pytiled_parser.properties, "ObjectRefProperty"):
    raise RuntimeError("Please install the latest patched version of pytiled_parser from third_party/.")

def list_maps():
    ret = {}
    for (dirpath, dirnames, filenames) in os.walk(os.path.join(environ.SRC_DIR, "map")):
        for fn in filenames:
            groups = re.match("""^map_exported_(.*)\.tmx$""", fn)
            if groups:
                ret[groups.group(1)] = os.path.join(dirpath, fn)
    return ret

class Layer(Component):
    def __init__(self, name: str):
        Component.__init__(self)
        self.name: str = name

    @property
    def tmx_data(self):
        return self.entity.tmx_data

class TileLayer(Layer):
    sprite_list = Unserialized()
    spatial_hash = Unserialized()

    @environ.client_only
    def draw(self):
        self.sprite_list.draw(filter=environ.arcade.gl.gl.GL_NEAREST, pixelated=True)

    def init_unserialized(self, deserializer):
        super().init_unserialized(deserializer)
        self.spatial_hash = deserializer.context.spatial_hashes[self.name]
        self.spatial_hash.entity = self.entity
        if environ.environ == "client":
            self.sprite_list = deserializer.context.pyarcade_tilemap.sprite_lists[self.name]


def make_spatial_hash(tmx_data, game) -> spatial_hash.SpatialHash:
    map_array = tmx_data.data
    s = spatial_hash.SpatialHash()

    for row_index, row in enumerate(map_array):
        for column_index, item in enumerate(row):
            # Check for an empty tile
            if item == 0:
                continue

            tile = game.get_tile(item)

            t = Transform()
            t.position = Vector2f(column_index, row_index) * Vector2f(
                tile.tileset.tile_width, tile.tileset.tile_height)
            t.size = Vector2f(tile.tileset.tile_width, tile.tileset.tile_height)
            t.base_size = t.size
            t.rotation_anchor = alignment_to_vector("center")
            t.y += tile.tileset.tile_height
            t.flip_x = utils.is_flipped_horizontally(item)
            t.flip_y = utils.is_flipped_vertically(item)

            colliders = collision.make_colliders_from_tile(tile)
            for collider in colliders:
                tcollider = t.transform_points(collider)
                s.add(tcollider)

    return s


def make_tile_layer(tmx_data, game) -> Entity:
    layer_entity = Entity(tmx_data.name)
    layer_entity.tmx_data = tmx_data
    layer = TileLayer(tmx_data.name)
    layer_entity.add_component(layer)

    layer_entity.transform.base_size = Vector2f(
        tmx_data.size.width, tmx_data.size.height) * Vector2f(
        game.tmx_map.tile_size.width, game.tmx_map.tile_size.height)
    layer_entity.transform.size = Vector2f(layer_entity.transform.base_size)
    layer_entity.transform.y = layer_entity.transform.size.y

    if tmx_data.properties and tmx_data.properties.get("solid", True) == False:
        layer.spatial_hash = None
    else:
        layer.spatial_hash = make_spatial_hash(tmx_data, game)
        layer.spatial_hash.entity = layer_entity

    if environ.environ == "client":
        layer.sprite_list = game.pyarcade_tilemap.sprite_lists[tmx_data.name]
    else:
        layer.sprite_list = None

    return layer_entity

class ObjectLayer(Layer):
    sprite_list = Unserialized()
    def __init__(self, tmx_data, *args, **kwargs):
        if environ.environ == "client":
            self.sprite_list = environ.arcade.SpriteList(use_spatial_hash=False)
        else:
            self.sprite_list = None

        self.colliding_layers: Tuple = None
        if tmx_data.properties and 'colliding_layers' in tmx_data.properties:
            self.colliding_layers = tuple(x.strip() for x in tmx_data.properties['colliding_layers'].split(","))

        super().__init__(tmx_data.name, *args, **kwargs)
        pass

    def init_unserialized(self, deserializer):
        super().init_unserialized(deserializer)
        if environ.environ == "client":
            self.sprite_list = environ.arcade.SpriteList(use_spatial_hash=False)

    def draw(self) -> bool:
        entity: gametree.Entity = self.entity
        entity.dispatch_to_tree("update_sprite")
        self.sprite_list.draw(filter=environ.arcade.gl.gl.GL_NEAREST, pixelated=True)
        return True


class Root(Component):
    _tile_layers = serialize.Unserialized()
    _entity_layers = serialize.Unserialized()

    def __init__(self):
        super().__init__()
        self._tile_layers: Tuple = None
        self._object_layers: Tuple = None

    def init_unserialized(self, deserializer):
        super().init_unserialized(deserializer)
        self._tile_layers = None
        self._object_layers = None

    @property
    def tile_layers(self) -> Iterable[ObjectLayer]:
        if self._tile_layers is None:
            tile_layers = []
            for child in self.entity.children:
                comp = child.get_component(TileLayer)
                if comp is not None:
                    tile_layers.append(comp)
            self._tile_layers = tuple(x for x in tile_layers)
        return self._tile_layers

    @property
    def object_layers(self) -> Iterable[ObjectLayer]:
        if self._object_layers is None:
            object_layers = []
            for child in self.entity.children:
                comp = child.get_component(ObjectLayer)
                if comp is not None:
                    object_layers.append(comp)
            self._object_layers = tuple(x for x in object_layers)
        return self._object_layers

    @property
    def entity_layers(self) -> Iterable[ObjectLayer]:
        return self.object_layers


def alignment_to_vector(alignment) -> Vector2:
    if alignment == "bottomleft":
        return Vector2f(0, 0)
    if alignment == "left":
        return Vector2f(0, 0.5)
    if alignment == "topleft":
        return Vector2f(0, 1)
    if alignment == "bottom":
        return Vector2f(0.5, 0)
    if alignment == "center":
        return Vector2f(0.5, 0.5)
    if alignment == "topleft":
        return Vector2f(0.5, 1)
    if alignment == "bottomright":
        return Vector2f(1, 0)
    if alignment == "right":
        return Vector2f(1, 0.5)
    if alignment == "topright":
        return Vector2f(1, 1)
    raise RuntimeError(f"Expected alignment string, got f{alignment}")

def make_transform(tmx_object, game) -> gametree.Transform:
    t = Transform()
    t.x = tmx_object.coordinates.x
    t.y = tmx_object.coordinates.y
    t.size.x = tmx_object.size.width
    t.size.y = tmx_object.size.height
    t.rotation = tmx_object.rotation

    if hasattr(tmx_object, "gid"):
        t.flip_x = utils.is_flipped_horizontally(tmx_object.gid)
        t.flip_y = utils.is_flipped_vertically(tmx_object.gid)

        tileset = game.get_tile(tmx_object).tileset
        t.base_size.x = tileset.tile_width
        t.base_size.y = tileset.tile_height
        t.rotation_anchor = alignment_to_vector(tileset.alignment)
        t.position += t.size * t.rotation_anchor * Vector2f(-1, 1)
    else:
        t.base_size.x = t.size.x
        t.base_size.y = t.size.y
    if not isinstance(tmx_object, pytiled_parser.tiled_object.Tile):
        t.y += tmx_object.size.height
        t.rotation_anchor = alignment_to_vector("topleft")
    return t


def find_tileset(tmx_map: pytiled_parser.tiled_map.TiledMap, gid: int):
    tileset_keys = list(tmx_map.tilesets.keys())
    tileset_num = tileset_keys[bisect.bisect_right(tileset_keys, gid) - 1]
    return tmx_map.tilesets[tileset_num]


def init_entity(entity, tmx_map: pytiled_parser.tiled_map.TiledMap, tmx_object, game, entities_by_id):
    entity.id = tmx_object.id
    entity.tmx_data = tmx_object
    if hasattr(tmx_object, "gid") and tmx_object.gid is not None:
        entity.gid = tmx_object.gid

    entity.transform = make_transform(tmx_object, game)

    if entity.original_frameset is not None:
        entity.frameset = entity.original_frameset

    for name, prop in tmx_object.properties.items():
        if not isinstance(prop, pytiled_parser.properties.ClassProperty):
            continue

        if prop.propertytype not in gametree.component_types:
            raise RuntimeError(f"Attempt to instantiate component of type {prop.propertytype}; no matching component type exists. Available component types: {gametree.component_types.keys()}")

        component_type = gametree.component_types[prop.propertytype]
        if hasattr(component_type, "create_from_tmx"):
            component = component_type.create_from_tmx(prop, entity)
        else:
            component = component_type()
            for k, v in prop.items():
                if isinstance(v, pytiled_parser.properties.ObjectRefProperty):
                    try:
                        v = entities_by_id[int(v)]
                    except KeyError as e:
                        raise KeyError(f"Could not find referenced entity with id {int(v)} (referenced by {entity.name} id={entity.id}). Make sure that the referenced object actually exists, and both the referencing object and the referenced object are on the same layer.")
                setattr(component, k, v)
        entity.add_component(component)

    for name, prop in tmx_object.properties.items():
        if name == "frameset":
            continue  # Framesets are handled separately

        if isinstance(prop, pytiled_parser.properties.ClassProperty):
            entity.class_name = name
            continue

        if isinstance(prop, pytiled_parser.properties.ObjectRefProperty):
            prop = entities_by_id[int(prop)]

        setattr(entity, name, prop)

    if isinstance(tmx_object, pytiled_parser.tiled_object.Tile):
        collider: collision.Collider
        if entity.framesets:
            collider = collision.MultiCollider()
        else:
            collider = collision.SingleCollider(tmx_object)
        entity.add_component(collider)

    else:
        collider_vec = collision.make_collider_from_hitbox(tmx_object)
        if collider_vec is not None:
            # X/Y positions are double-counted in the object's transform and the hitbox
            collider_vec = [Vector2f(p.x - entity.transform.x, p.y - entity.transform.y + entity.transform.size.y) for p in collider_vec]
            entity.add_component(collision.ManualCollider([collider_vec], solid=tmx_object.properties.get('solid', True)))


    return entity


def make_object_layer(tmx_map: pytiled_parser.tiled_map.TiledMap, tmx_data: pytiled_parser.layer.ObjectLayer, game) -> Entity:
    layer_entity = Entity(tmx_data.name)
    layer_entity.tmx_data = tmx_data
    layer = ObjectLayer(tmx_data)
    layer_entity.add_component(layer)
    entities_by_id = {}
    for tmx_object in tmx_data.tiled_objects:
        # Allow certain entities to be skipped. These entities are used to force tilesets to appear in the map,
        # and that's it.
        if tmx_object.properties.get("skip_in_game", False):
            continue

        entities_by_id[tmx_object.id] = Entity(tmx_object.name or str(tmx_object.id))

    entities = []
    for tmx_object in tmx_data.tiled_objects:
        entity = entities_by_id.get(tmx_object.id, None)
        if entity is None:
            continue
        init_entity(entity, tmx_map, tmx_object, game, entities_by_id)
        entities.append(layer_entity.add_child(entity))

    for e in entities:
        if isinstance(e.tmx_data, pytiled_parser.tiled_object.Tile):
            r: renderer.Renderer
            if e.framesets:
                r = renderer.MultiRenderer()
            else:
                r = renderer.SingleRenderer(e.tmx_data)
                if r.sprite is not None and r.sprite.animated:
                    # TODO: fix this
                    raise NotImplementedError("Animations don't work with SingleRenderer (they should, this should be investigated). Set up a frameset instead, so you get a MultiRenderer.")
            e.add_component(r)

    return layer_entity

def fixup_tilesets(tmx_map: pytiled_parser.tiled_map.TiledMap):
    for tileset in tmx_map.tilesets.values():
        if tileset.tiles is None:
            tileset.tiles = {}
        for tile in tileset.tiles.values():
            tile.tileset = tileset
        if tileset.image is not None:
            tileset.tile_count = (tileset.image_height // tileset.tile_height) * (tileset.image_width // tileset.tile_width)
            for i in range(0, tileset.tile_count):
                if i not in tileset.tiles:
                    tile = pytiled_parser.Tile(id=(i), tileset=tileset)
                    tileset.tiles[i] = tile

def load_map(path_or_tmx_map: Union[pytiled_parser.tiled_map.TiledMap, str]):
    if isinstance(path_or_tmx_map, str):
        path_or_tmx_map = pytiled_parser.parse_map(pathlib.Path(path_or_tmx_map))
        fixup_tilesets(path_or_tmx_map)
    return _load_map(path_or_tmx_map)


def make_spec(tmx_data, game) -> Dict[Tuple[int, int], Dict[str, str]]:
    """
    Returns:
        Dict from (x, y) integer tile coordinates to property dict of the
        spec tile at those coordinates.
    """
    map_array = tmx_data.data

    ret = {}

    for row_index, row in enumerate(map_array):
        for column_index, item in enumerate(row):
            # Check for an empty tile
            if item == 0:
                continue

            tile = game.get_tile(item)
            if tile.properties:
                ret[(column_index, row_index)] = tile.properties

    return ret

def _load_map(tmx_map: pytiled_parser.tiled_map.TiledMap):
    game = game_mod.Game()
    game.tmx_map = tmx_map
    environ.game = game
    pyarcade_tilemap = None
    if environ.environ == "client":
        pyarcade_tilemap = environ.arcade.tilemap.tilemap.TileMap(tiled_map=tmx_map, hit_box_algorithm="None")
        game.pyarcade_tilemap = pyarcade_tilemap

    root = Entity("root")
    root.add_component(Root())
    game.root = root

    for tmx_layer in tmx_map.layers:
        layer = None

        if isinstance(tmx_layer, pytiled_parser.layer.TileLayer):
            if tmx_layer.properties and tmx_layer.properties.get("spec", None):
                if hasattr(game, "spec") and game.spec:
                    raise RuntimeError("Only one layer with property spec=True allowed per map.")
                game.spec = make_spec(tmx_layer, game)
                continue
            else:
                layer = make_tile_layer(tmx_layer, game)

        elif isinstance(tmx_layer, pytiled_parser.layer.ObjectLayer):
            layer = make_object_layer(tmx_map, tmx_layer, game)

        else:
            sys.stderr.write(f"Unsupported layer {tmx_layer}\n")
            continue

        root.add_child(layer)



    return game

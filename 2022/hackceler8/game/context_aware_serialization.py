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

import serialize
import pytiled_parser
import map_loader
import environ
import copy
import utils
import bisect
import game
import os

def TiledMap_serialize(obj, serializer, proto):
    """A TiledMap is just serialized as a path to the TiledMap in question."""
    proto.custom = str(obj.map_file).encode("utf-8")

def TiledMap_deserialize(typ, deserializer, entity_id, o):
    """Only 'deserialize' a TiledMap if it already exists in our context."""
    path = o.custom.decode("utf-8")
    if os.path.basename(path) != os.path.basename(str(deserializer.context.tmx_map.map_file)):
        raise RuntimeError(f"Deserializing context for wrong TiledMap {path}; expecting {deserializer.context.tmx_map.map_file}")
    return deserializer.context.tmx_map

serialize.register_custom_serializer(pytiled_parser.tiled_map.TiledMap, TiledMap_serialize, TiledMap_deserialize)

def Tile_serialize(obj, serializer, proto):
    """A Tiled Tile (for entities) is serialized as its ID only."""
    proto.custom = str(obj.id).encode("utf-8")

def Tile_deserialize(typ, deserializer, entity_id, o):
    obj_id = int(o.custom.decode("utf-8"))
    if obj_id not in deserializer.context.tmx_objects:
        raise RuntimeError(f"Cannot deserialize unknown object id {obj_id}.")
    return deserializer.context.tmx_objects[obj_id]

serialize.register_custom_serializer(pytiled_parser.tiled_object.Tile, Tile_serialize, Tile_deserialize)

def Layer_serialize(obj, serializer, proto):
    """A Tiled Layer is serialized as its name only."""
    proto.custom = obj.name.encode("utf-8")

def Layer_deserialize(typ, deserializer, entity_id, o):
    name = o.custom.decode("utf-8")
    if name not in deserializer.context.tmx_layers:
        raise RuntimeError(f"Cannot deserialize unknown layer {name}.")
    return deserializer.context.tmx_layers[name]

def ObjectRefProperty_serialize(obj, serializer, proto):
    proto.custom = obj.encode("utf-8")

def ObjectRefProperty_deserialize(typ, deserializer, entity_id, o):
    val = o.custom.decode("utf-8")
    return typ(val)

serialize.register_custom_serializer(pytiled_parser.layer.Layer,
    Layer_serialize, Layer_deserialize)
serialize.register_custom_serializer(pytiled_parser.layer.TileLayer,
    Layer_serialize, Layer_deserialize)
serialize.register_custom_serializer(pytiled_parser.layer.ImageLayer,
    Layer_serialize, Layer_deserialize)
serialize.register_custom_serializer(pytiled_parser.layer.ObjectLayer,
    Layer_serialize, Layer_deserialize)
serialize.register_custom_serializer(pytiled_parser.properties.ObjectRefProperty,
    ObjectRefProperty_serialize, ObjectRefProperty_deserialize)

serialize.register_custom_serializer(pytiled_parser.tiled_object.Point,
    serialize.simple_custom_serializer, serialize.simple_custom_deserializer)
serialize.register_custom_serializer(pytiled_parser.tiled_object.Rectangle,
    serialize.simple_custom_serializer, serialize.simple_custom_deserializer)
serialize.register_custom_serializer(pytiled_parser.common_types.Color,
    serialize.namedtuple_custom_serializer, serialize.namedtuple_custom_deserializer)
serialize.register_custom_serializer(pytiled_parser.common_types.Size,
    serialize.namedtuple_custom_serializer, serialize.namedtuple_custom_deserializer)
serialize.register_custom_serializer(pytiled_parser.common_types.OrderedPair,
    serialize.namedtuple_custom_serializer, serialize.namedtuple_custom_deserializer)

class Context(game.GameBase):
    sprites = serialize.Unserialized()
    spatial_hashes = serialize.Unserialized()
    def __init__(self, tmx_map):
        super().__init__()
        self.tmx_map = tmx_map
        self.tmx_layers = {}
        self.tmx_objects = {}
        self.sprites = {}
        self.spatial_hashes = {}
        if environ.environ == "client":
            self.pyarcade_tilemap = environ.arcade.tilemap.tilemap.TileMap(tiled_map=self.tmx_map, hit_box_algorithm="None")

        for layer in self.tmx_map.layers:
            self.tmx_layers[layer.name] = layer

            if isinstance(layer, pytiled_parser.layer.ObjectLayer):
                for obj in layer.tiled_objects:
                    self.tmx_objects[obj.id] = obj
            if isinstance(layer, pytiled_parser.layer.TileLayer):
                spatial_hash = map_loader.make_spatial_hash(layer, self)
                self.spatial_hashes[layer.name] = spatial_hash
        if environ.environ == "client":
            for name, layer in self.tmx_layers.items():
                if not isinstance(layer, pytiled_parser.layer.ObjectLayer):
                    continue
                for o in layer.tiled_objects:
                        if isinstance(o, pytiled_parser.tiled_object.Tile):
                            sprite = self.pyarcade_tilemap.sprite_lists[layer.name].sprite_list[0]
                            sprite.remove_from_sprite_lists()
                            self.sprites[o.id] = sprite









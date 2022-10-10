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

import bisect
from typing import Optional, Any

import pytiled_parser
import serialize
import map_loader
import keys
from components import player, chest, fireplace, zone, grate_door, flag, collectable, npc, key, connector, returner, logic, teleporter
from components import save as component_save
import environ
import collision
from typing import Optional, Union, Dict, Tuple
from gametree import *
import sys

FPS = 60
DELTA_TIME = 1.0 / FPS

# In seconds
DEATH_DURATION = 1

class GameBase(serialize.SerializableObject):
    pyarcade_tilemap = serialize.Unserialized()

    def __init__(self):
        super().__init__()
        self.tmx_map: Optional[pytiled_parser.TiledMap] = None
        self.pyarcade_tilemap = None
        self.spec = {}

    def find_tileset(self, name_or_gid: Union[int, str]) -> Optional[pytiled_parser.Tileset]:
        assert self.tmx_map is not None
        if isinstance(name_or_gid, int):
            gid = utils.masked_gid(name_or_gid)
            tileset_keys = list(self.tmx_map.tilesets.keys())
            tileset_num = tileset_keys[bisect.bisect_right(tileset_keys, name_or_gid) - 1]
            return self.tmx_map.tilesets[tileset_num]
        if isinstance(name_or_gid, str):
            for tileset in self.tmx_map.tilesets.values():
                if tileset.name == name_or_gid:
                    return tileset
            return None
        raise RuntimeError(f"Expected int or str, got {type(name_or_gid)}")

    def find_frameset(self, frameset: str, tileset: pytiled_parser.Tileset = None) -> Optional[pytiled_parser.Tile]:
        assert self.tmx_map is not None
        if tileset is None:
            for t in self.tmx_map.tilesets.values():
                ret = self.find_frameset(frameset, t)
                if ret is not None:
                    return ret
            return None

        for tile in tileset.tiles.values():
            if tile.properties is None:
                continue
            f = tile.properties.get('frameset', None)
            if f == frameset:
                return tile
        return None

    def get_tile(self, gid: int) -> pytiled_parser.Tile:
        gid = utils.masked_gid(gid)
        tileset = self.find_tileset(gid)
        assert tileset is not None
        if (gid - tileset.firstgid) not in tileset.tiles:
            sys.stderr.write(f"Missing id {gid - tileset.firstgid}\n")
        tile = tileset.tiles[gid - tileset.firstgid]
        return tile

    def gid_to_tile_reference(self, gid: int) -> Tuple[str, int]:
        """Convert a gid to a (tileset_name, relative_gid) pair. relative_gid has flip indicator bits."""
        masked_gid = utils.masked_gid(gid)
        tileset = self.find_tileset(masked_gid)
        assert tileset is not None
        if (masked_gid - tileset.firstgid) not in tileset.tiles:
            sys.stderr.write(f"Missing id {gid - tileset.firstgid}\n")
        return (tileset.name, gid - tileset.firstgid)

    def get_tile_by_tile_reference(self, tileset_name: str, gid: int) -> pytiled_parser.Tile:
        gid = utils.masked_gid(gid)
        tileset = self.find_tileset(tileset_name)
        if tileset is None:
            raise RuntimeError(f"Could not find tileset {tileset} in map {self.tmx_map.map_file}. " +
                               "If this is from a collectible item, make sure that at least one tile references "
                               "the collectible item's tileset in every map, e.g. stick a copy of the item somewhere.")
        if gid not in tileset.tiles:
            sys.stderr.write(f"Missing id {gid}\n")
        tile = tileset.tiles[gid]
        return tile



    @environ.client_only
    def make_sprite(self, tile: pytiled_parser.Tile) -> sprites.Sprite:
        ret = self.pyarcade_tilemap._create_sprite_from_tile(tile, hit_box_algorithm="None",
                                                             custom_class=sprites.Sprite,
                                                             custom_class_args={"tile": tile})
        ret.remove_from_sprite_lists()
        return ret

    @environ.client_only
    def make_texture(self, tile):
        # This can be made more efficient by directly creating the texture
        sprite = self.make_sprite(tile)
        return sprite.texture

    @environ.client_only
    def make_multi_sprite(self, framesets: dict[str, Frameset], flipped_horizontally: bool, flipped_vertically: bool, tileset: pytiled_parser.Tileset = None):
        additional_sprites = {}
        for name, frameset in framesets.items():
            t: pytiled_parser.Tile = self.find_frameset(frameset.frameset, tileset)

            t.flipped_horizontally = flipped_horizontally != frameset.flipped_horizontally
            t.flipped_vertically = flipped_vertically != frameset.flipped_vertically

            additional_sprites[name] = self.make_sprite(t)

        if additional_sprites:
            return sprites.MultiSprite(additional_sprites)

    @property
    def map_size(self) -> Vector2:
        assert self.tmx_map is not None
        map_size_tiles = self.tmx_map.map_size
        tile_size = self.tmx_map.tile_size
        return Vector2i(x=map_size_tiles.width * tile_size.width, y=map_size_tiles.height * tile_size.height)

    @property
    def tile_size(self) -> Vector2:
        assert self.tmx_map is not None
        return Vector2i(self.tmx_map.tile_size.width, self.tmx_map.tile_size.height)

    def pre_init_unserialized(self, deserializer):
        if environ.environ == "client":
            self.pyarcade_tilemap = deserializer.context.pyarcade_tilemap
        else:
            self.pyarcade_tilemap = None

    @classmethod
    def deserialize(cls, deserializer, entity_id: int, entity):
        obj = cls.__new__(cls)
        deserializer.add_to_cache(entity_id, obj)
        obj.pre_init_unserialized(deserializer)
        obj.deserialize_state_fields(deserializer, entity_id, entity)
        obj.init_unserialized(deserializer)
        return obj


@dataclasses.dataclass
class _CollisionEntry:
    stamp: int = -1
    pairs: Dict[int, Any] = dataclasses.field(default_factory=dict)


class Game(GameBase):
    held_keys = serialize.Unserialized()
    current_collisions = serialize.Unserialized()
    _modification_stamp = serialize.Unserialized()
    _last_collision_check_results = serialize.Unserialized()
    collisions_checked = serialize.Unserialized()

    def __init__(self):
        super().__init__()
        self.root: Optional[Entity] = None
        self.held_keys: set[int] = set()
        self.current_collision_pairs: dict[Entity, Entity] = dict()
        self.tick_number: int = 0
        self._modification_stamp: int = 0
        self._last_collision_check_results = collections.defaultdict(_CollisionEntry)
        self.collisions_checked: int = 0
        self.request_map_change = None
        self.save_allowed = 0
        self.now_talking_to = None

        self._player = None
        self._default_for_new_objects = None

        self.player_dead = False
        self.death_timesamp: int = 0

    def on_key_press(self, key, modifiers):
        self.held_keys.add(key)
        # Not implemented on server side. Use a latch instead.
        #self.root.dispatch_to_tree("on_key_press", key, modifiers)

    def on_key_release(self, key, modifiers):
        if key in self.held_keys:
            self.held_keys.discard(key)
            # Not implemented on server side
            #self.root.dispatch_to_tree("on_key_release", key, modifiers)

    def tick(self):
        if self.player_dead and self.tick_number > self.death_timesamp + DEATH_DURATION * FPS:
            self.player_dead = False
            self._player.reset_to_spawn()

        self.root.dispatch_to_tree("tick")

        if not self.player_dead:
            self.root.dispatch_to_tree("while_keys_held", self.held_keys)

        # We use a dict here instead of a set as sets are unordered which might
        # mess up the server state validation.
        collision_pairs = dict()
        self.collisions_checked = 0

        root: map_loader.Root = self.root.get_component(map_loader.Root)

        all_tile_layers = root.tile_layers

        for entity_layer in root.entity_layers:
            all_colliders = entity_layer.entity.get_components_in_children(collision.Collider)
            for left in all_colliders:
                prev_results = self._last_collision_check_results[id(left)]
                if prev_results.stamp < left.entity.transform_modified:
                    prev_results.stamp = left.entity.transform_modified
                    prev_results.pairs = dict()
                    for tl in all_tile_layers:
                        if tl.spatial_hash is None:
                            continue
                        if entity_layer.colliding_layers is None or tl.name in entity_layer.colliding_layers:
                            self.collisions_checked += 1
                            if left.test_intersection(tl.spatial_hash):
                                collision_pairs[(left.entity, tl.entity)] = 0
                                prev_results.pairs[(left.entity, tl.entity)] = 0
                else:
                    collision_pairs.update(prev_results.pairs)

        all_colliders = self.root.get_components_in_children(collision.Collider)
        for i in range(len(all_colliders)):
            for j in range(i + 1, len(all_colliders)):
                left = all_colliders[i]
                right = all_colliders[j]
                prev_results = self._last_collision_check_results[
                                   (id(left), id(right))]
                if prev_results.stamp < left.entity.transform_modified or prev_results.stamp < right.entity.transform_modified:
                    prev_results.stamp = self.get_modification_stamp()
                    prev_results.pairs = dict()
                    self.collisions_checked += 1
                    if left.test_intersection(right):
                        collision_pairs[(left.entity, right.entity)] = 0
                        prev_results.pairs[(left.entity, right.entity)] = 0
                else:
                    collision_pairs.update(prev_results.pairs)

        for pair in collision_pairs.keys():
            if pair not in self.current_collision_pairs.keys():
                pair[0].dispatch_to_components("on_collision_enter", pair[1])
                pair[1].dispatch_to_components("on_collision_enter", pair[0])
            pair[0].dispatch_to_components("while_colliding", pair[1])
            pair[1].dispatch_to_components("while_colliding", pair[0])


        for pair in self.current_collision_pairs.keys():
            if pair not in collision_pairs.keys():
                pair[0].dispatch_to_components("on_collision_exit", pair[1])
                pair[1].dispatch_to_components("on_collision_exit", pair[0])

        self.current_collision_pairs = collision_pairs

        self.tick_number += 1

    def pre_init_unserialized(self, deserializer):
        super().pre_init_unserialized(deserializer)
        self._modification_stamp = 0

    def init_unserialized(self, *args, **kwargs):
        self.held_keys = set()
        self._last_collision_check_results = collections.defaultdict(_CollisionEntry)
        self.collisions_checked = 0

    def lookup_entity_by_id(self, entity_id: int) -> Entity:
        entity_id = int(entity_id)
        obj_layer = environ.game.root.get_children("ObjectLayer[Object Layer 1]")[0]
        for entity in obj_layer.children:
            if entity.tmx_data.id == entity_id:
                return entity
        raise RuntimeError(f"Could not find entity {entity_id}.")

    @property
    def default_for_new_objects(self):
        if self._default_for_new_objects is None:
            self._default_for_new_objects = self._find_default_for_new_objects(self.root)
        return self._default_for_new_objects

    def _find_default_for_new_objects(self, node):
        if node.tmx_data is not None and node.tmx_data.properties and node.tmx_data.properties.get('default_for_new_objects', False):
            return node
        for child in node.children:
            ret = self._find_default_for_new_objects(child)
            if ret is not None:
                return ret

    @property
    def player(self):
        if self._player is None or self._player.entity.parent is None:
            self._player = self.root.get_component_in_children(player.Player)
        return self._player

    def get_modification_stamp(self):
        """Returns a perpetually incrementing sentinel. Every call will be
           greater than all previous calls. Can be used for cache invalidation."""
        self._modification_stamp += 1
        return self._modification_stamp

    def kill_player(self):
        self.death_timesamp = self.tick_number
        self.player_dead = True

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

import math
import sys

from gametree import Frameset, Component, Entity, Vector2f
import keys as keys_enum
import game
import collision
import map_loader
import utils
import serialize
from components import collectable
from typing import List
import environ


def gen_framesets() -> dict[str, Frameset]:
    regular_prefixes = ["up", "upright", "right", "downright", "down", "upleft", "left", "downleft"]
    inverted_prefixes = []
    suffixes = ["stand", "run"]
    ret = {}
    for s in suffixes:
        for p in regular_prefixes:
            name = f'{p}_{s}'
            ret[name] = Frameset(frameset=name)
        for p in inverted_prefixes:
            name = f'{p}_{s}'
            ret[name] = Frameset(frameset=name.replace("left", "right"), flipped_horizontally=True)

    return ret


class Player(Component):
    additional_framesets: dict[str, Frameset] = gen_framesets()
    entity: Entity

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.facing: str = "down"
        self._interaction: utils.Latch = utils.Latch()
        self.level_persistent = {"inventory": []}

    def update_animation(self, frameset: str):
        if frameset != self.entity.frameset:
            self.entity.frameset = frameset

    def tick(self):
        #TODO(ipudney): Only call this if the player's transform has been modified
        self.update_spec()

    def center_feet(self):
        t = self.entity.transform
        return Vector2f(t.position.x + t.size.x / 2, t.position.y - t.size.y * 4/64)

    def update_spec(self):
        center_feet = self.center_feet()
        tile_coords = (int(center_feet.x / 32), int(center_feet.y / 32))
        spec_properties = environ.game.spec.get(tile_coords, None)
        if spec_properties is not None:
            environ.game.root.dispatch_to_tree("player_in_spec", spec_properties)

    def player_in_spec(self, spec_properties):
        if "print_spec" in spec_properties:
            print(spec_properties)
        if "z_level" in spec_properties:
            z_level = spec_properties["z_level"]
            if self.entity.parent.name != z_level:
                root: map_loader.Root = environ.game.root.get_component(map_loader.Root)
                for layer in root.entity_layers:
                    if layer.name == z_level:
                        self.entity.parent.remove_child(self.entity)
                        layer.entity.add_child(self.entity)
                        break
                else:
                    raise RuntimeError(f"Attempted to move player to layer {z_level}, no such layer exists.")



    def while_keys_held(self, keys_: list[int]):
        keys = set(keys_)

        # Interact with something.
        self._interaction.update(keys_enum.E in keys)

        # Opposite key presses cancel
        if keys_enum.A in keys and keys_enum.D in keys:
            keys.remove(keys_enum.A)
            keys.remove(keys_enum.D)
        if keys_enum.W in keys and keys_enum.S in keys:
            keys.remove(keys_enum.W)
            keys.remove(keys_enum.S)

        velocity = self.speed * game.DELTA_TIME
        velocity_sqrt2 = velocity / math.sqrt(2)

        # Handle the 8 directions
        if keys_enum.A in keys and keys_enum.W in keys:
            self.entity.transform.position.x -= velocity_sqrt2
            self.entity.transform.position.y -= velocity_sqrt2
            self.facing = "upleft"
            animation = f'{self.facing}_run'
        elif keys_enum.D in keys and keys_enum.W in keys:
            self.entity.transform.position.x += velocity_sqrt2
            self.entity.transform.position.y -= velocity_sqrt2
            self.facing = "upright"
            animation = f'{self.facing}_run'
        elif keys_enum.D in keys and keys_enum.S in keys:
            self.entity.transform.position.x += velocity_sqrt2
            self.entity.transform.position.y += velocity_sqrt2
            self.facing = "downright"
            animation = f'{self.facing}_run'
        elif keys_enum.A in keys and keys_enum.S in keys:
            self.entity.transform.position.x -= velocity_sqrt2
            self.entity.transform.position.y += velocity_sqrt2
            self.facing = "downleft"
            animation = f'{self.facing}_run'
        elif keys_enum.A in keys:
            self.entity.transform.position.x -= velocity
            self.facing = "left"
            animation = f'{self.facing}_run'
        elif keys_enum.D in keys:
            self.entity.transform.position.x += velocity
            self.facing = "right"
            animation = f'{self.facing}_run'
        elif keys_enum.W in keys:
            self.entity.transform.position.y -= velocity
            self.facing = "up"
            animation = f'{self.facing}_run'
        elif keys_enum.S in keys:
            self.entity.transform.position.y += velocity
            self.facing = "down"
            animation = f'{self.facing}_run'
        else:
            animation = f'{self.facing}_stand'

        self.update_animation(animation)

    def on_collision_enter(self, other: Entity):
        pass

    def while_colliding(self, other: Entity):
        other_collider = other.get_component(collision.Collider)
        if other_collider is None:
            # Using a spatial hash
            # TODO(ipudney): Make this less special-case-y
            other_collider = other.get_component(map_loader.TileLayer).spatial_hash

        if self._interaction.was_pressed:
            other.dispatch_to_components("on_player_interaction")

        if other_collider.solid and not other.get_component(collectable.Collectable):
            collider = self.entity.get_component(collision.Collider)

            mtv = collider.minimum_translation_vector(other_collider)
            if mtv is None:
                sys.stderr.write("Got collision from shapely that doesn't match MTV.")
                return
            self.transform.position += mtv

    def on_collision_exit(self, other: Entity):
        pass

    @property
    def inventory(self) -> List[collectable.Collectable]:
        return self.level_persistent["inventory"]

    def use_item(self, item_idx):
        remove = self.inventory[item_idx].entity.dispatch_to_components("on_use")
        if remove:
            del self.inventory[item_idx]
        if environ.environ == "client":
            environ.client.net.send("use_item", item_idx)

    def reset_to_spawn(self):
        original_coordinates = self.entity.tmx_data.coordinates
        self.entity.transform.position.x = original_coordinates.x
        self.entity.transform.position.y = original_coordinates.y

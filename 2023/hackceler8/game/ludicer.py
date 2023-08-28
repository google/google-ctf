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

from copy import copy
from enum import Enum
import json
import logging
import random

import arcade
import xxhash

from components import textbox
from components.inventory import Inventory
from engine import physics
from engine.combat import CombatSystem
from engine.map_switcher import MapSwitch
from map_loading import maps

PLAYER_MOVEMENT = 16 * 10

GRAVITY = 1

PLATFORMER_TILE_SCALING = 1.0


class GameMode(Enum):
    MODE_PLATFORMER = "platformer"
    MODE_SCROLLER = "scroller"


class MagicItem(Enum):
    ITEM_PURPLE = "purple"


COLOR_LIST = [
    arcade.color.GREEN,
    arcade.color.RED,
    arcade.color.YELLOW,
]


class Ludicer():
    def __init__(self, net, is_server, rand_seed=1298472982523, debug=True):
        self.net = net
        self.is_server = is_server
        self.rand_seed = rand_seed
        random.seed(self.rand_seed)

        # persistent stuff
        self.items = []
        self.tics = 0

        self.maps_dict = maps.load()

        # We keep a pristine copy to allow for resets
        self.original_maps_dict = copy(self.maps_dict)

        self.mode_dict = {
            "base": GameMode.MODE_SCROLLER,
            "cctv": GameMode.MODE_PLATFORMER,
            "rusty": GameMode.MODE_PLATFORMER,
            "space": GameMode.MODE_PLATFORMER,
            "water": GameMode.MODE_PLATFORMER,
            "debug": GameMode.MODE_PLATFORMER
        }

        self.arena_mapping = {
            "purple_arena": "cctv",
            "red_arena": "rusty",
            "violet_arena": "space",
            "orange_arena": "water"
        }

        # variable stuff
        self.player = None
        self.player_last_base_position = None
        self.player_starting_position = {}

        # use this for solid, more/less static stuff
        self.objects = []

        # use this for stuff that should never move
        self.static_objs = []

        # use this for more complex interactions
        self.dynamic_artifacts = []

        self.mouse_position = None
        self.current_color = arcade.color.GREEN

        self.next_map = None
        self.current_map = "base"
        self.tiled_map = None
        self.tiled_map_background = None
        self.map_switch = None
        self.textbox = None
        self.current_mode = None
        self.state_hash = None

        self.tile_map = None
        self.scene = None
        self.player_sprite = None

        self.inventory = Inventory(self, is_server=self.is_server)
        self.combat_system = None
        self.physics_engine = None
        self.score = 0

        self.prev_display_inventory = False
        self.display_inventory = False
        self.pause = False

        self.newly_pressed_keys = set()
        self.prev_pressed_keys = set()
        self.tracked_keys = [
            # Movement
            arcade.key.W,
            arcade.key.A,
            arcade.key.S,
            arcade.key.D,

            # running
            arcade.key.LSHIFT,

            # Menu
            arcade.key.ESCAPE,
            arcade.key.R,
            arcade.key.I,
            arcade.key.P,

            # NPC
            arcade.key.E,
            arcade.key.ENTER,

            # Weapons
            arcade.key.SPACE,
        ]
        self.pressed_keys = set()

        self.setup()

    def dump_state(self):
        h = ""
        for i in self.objects + self.static_objs + \
                 self.dynamic_artifacts + [self.player] + self.items:
            h += i.hash
        h += xxhash.xxh64(str(self.tics)).hexdigest()
        self.state_hash = xxhash.xxh64(h.encode()).hexdigest()

    def reset_to_main_map(self):
        self.player.reset_movements()
        self.switch_maps("base")

    def setup(self):
        self.tile_map = None
        self.scene = None
        self.player_sprite = None
        self.objects = []
        self.dynamic_artifacts = []
        self.static_objs = []

        self.combat_system = None
        self.physics_engine = None
        self.score = 0
        self.current_mode = self.mode_dict[self.current_map]
        match self.current_mode:
            case GameMode.MODE_SCROLLER:
                self.setup_scroller()
            case GameMode.MODE_PLATFORMER:
                self.setup_platformer()

    def deep_reset_level(self, level_name: str):
        if level_name not in self.maps_dict:
            logging.critical(f"Unknown map {level_name}")
            return
        self.maps_dict[level_name] = self.original_maps_dict[level_name]

    def reset_current_level(self):
        if self.current_map == "base":
            self.player_last_base_position = None
        self.deep_reset_level(self.current_map)
        self.switch_maps(self.current_map)

    def setup_scroller(self):

        self.tiled_map, self.tiled_map_background = self.maps_dict[self.current_map][
                                                    :2]
        logging.debug(
            f"Loaded map {self.current_map} with {self.tiled_map.size},  (tile width:{self.tiled_map.tile_size}, total size: {self.tiled_map.map_size_pixels})")
        for o in self.tiled_map.dynamic_artifacts:
            self.dynamic_artifacts.append(o)

        self.combat_system = CombatSystem(self.tiled_map.weapons)

        for o in self.tiled_map.objs:

            if o.nametype == "Player":
                logging.debug("Have player")
                if self.current_map == "base" and self.player_last_base_position is not None:
                    x, y = self.player_last_base_position
                    o.place_at(x, y)
                elif self.current_map in self.player_starting_position:
                    x, y = self.player_starting_position[self.current_map]
                    o.place_at(x, y)
                else:
                    self.player_starting_position[self.current_map] = (o.x, o.y)
                self.player = o
                self.player.base_x_speed = PLAYER_MOVEMENT
                self.player.base_y_speed = PLAYER_MOVEMENT
                self.combat_system.player = self.player

            else:
                self.objects.append(o)

        self.static_objs = self.tiled_map.static_objs

        self.physics_engine = physics.PhysicsEngine(
            platformer_rules=(self.current_mode == GameMode.MODE_PLATFORMER),
            objects=[self.player] + self.objects, qt=self.tiled_map.qt,
            obj_map=self.tiled_map.obj_map, static_objects=self.static_objs)
        self.physics_engine.env_tiles = self.tiled_map.env_tiles
        self.physics_engine.moving_platforms = self.tiled_map.moving_platforms

        logging.debug("Scroller setup complete")

    def setup_platformer(self):
        self.setup_scroller()
        self.player.base_y_speed = 320

    def switch_maps(self, new_map):
        if self.current_map == "base" and self.current_map != new_map:
            self.player_last_base_position = (self.player.prev_x, \
                                              self.player.prev_y)
        self.current_map = new_map
        logging.debug(self.current_map)

        def switch():
            self.setup()

        def cleanup():
            self.map_switch = None

        self.map_switch = MapSwitch(switch, cleanup)

    def display_textbox(self, text: str, choices=None, free_text_fun=None):
        if self.textbox is not None:  # Already displaying
            return

        def cleanup():
            self.textbox = None
            # Avoid opening the textbox immediately again
            if arcade.key.E in self.newly_pressed_keys:
                self.newly_pressed_keys.remove(arcade.key.E)

        self.textbox = textbox.Textbox(self.is_server, text, cleanup, choices,
                                       free_text_fun)

    def objects_frozen(self):
        return self.map_switch is not None or self.textbox is not None

    def send_game_info(self):
        if self.net is not None:
            logging.debug(f"{self.tics} : {self.pressed_keys}")
            msg = json.dumps({"tics": self.tics, "state": self.state_hash,
                              "keys": list(self.pressed_keys),
                              "text_input": self.get_text_input()}).encode()
            self.net.send_one(msg)

    def get_text_input(self):
        if self.is_server:
            logging.error(
                "Called get_text_input on server, should only be used on client")
            return
        if self.textbox is None or self.textbox.text_input is None:
            return None
        return self.textbox.text_input.text

    def set_text_input(self, text):
        if not self.is_server:
            logging.error(
                "Called set_text_input on client, should only be used on server")
            return
        if self.textbox is None or self.textbox.text_input is None:
            return
        self.textbox.text_input.text = text

    def tick(self):
        self.tics += 1
        if self.player.health <= 0:
            self.player.dead = True
        self.dump_state()
        self.newly_pressed_keys = self.pressed_keys.difference(self.prev_pressed_keys)
        self.prev_pressed_keys = self.pressed_keys.copy()

        self.prev_display_inventory = self.display_inventory
        if arcade.key.P in self.newly_pressed_keys:
            self.pause = not (self.pause)
        if arcade.key.I in self.newly_pressed_keys:
            self.display_inventory = not (self.display_inventory)
        if self.display_inventory:
            self.inventory.tick(self.newly_pressed_keys)
        if self.pause or self.display_inventory:
            return self.send_game_info()

        if self.map_switch is not None:
            self.map_switch.tick()
        if self.textbox is not None:
            self.textbox.tick(self.newly_pressed_keys)

        if self.objects_frozen():
            return self.send_game_info()

        if not self.player.dead:
            if arcade.key.ESCAPE in self.newly_pressed_keys:
                self.reset_to_main_map()
            elif arcade.key.R in self.newly_pressed_keys:
                self.reset_current_level()

        self.check_dynamic_proximities()
        self.check_proximities()

        for o in self.objects:
            o.tick()
        if self.player is not None:
            self.player.tick(self.pressed_keys,
                             self.newly_pressed_keys,
                             reset_speed=(self.current_mode == GameMode.MODE_SCROLLER))

        for ac in self.combat_system.active_projectiles:
            ac.tick()

        self.physics_engine.tick()
        self.combat_system.tick(self.newly_pressed_keys, self.tics)
        self.gather_items(self.physics_engine.tmp_loot)
        self.physics_engine.tmp_loot = []

        if self.physics_engine.exit_on_next:
            return self.switch_maps("base")

        return self.send_game_info()

    def gather_items(self, _items):
        for i in _items:
            self.items.append(i)
            if i in self.objects:
                logging.debug("Player received a new item!")
                self.objects.remove(i)

    def check_dynamic_proximities(self):
        for o in self.dynamic_artifacts:
            if o.modifier is not None:
                c, _ = o.collides(self.player)
                if c:
                    self.player.apply_modifier(o.modifier, 0)
                    continue
                current_distance = o.proximity(self.player)
                if current_distance < o.modifier.min_distance:
                    self.player.apply_modifier(o.modifier, current_distance)

    def check_proximities(self):
        for o in self.static_objs:
            c, _ = o.collides(self.player)
            if c:
                match o.nametype:
                    case "Arena":
                        if o.name in self.arena_mapping:
                            logging.debug(f"loading map {self.current_map}")
                            self.switch_maps(self.arena_mapping[o.name])
                            return

                        logging.warning(f"Arena {o.name} is not associated with \
                                                    any maps, r u cheating?")

                    case "ExitArea":
                        logging.debug(f"Player collided with {o.name}")
                        self.switch_maps("base")
                        return

        for o in self.objects:
            if o.blocking:
                c, _ = o.collides(self.player)
                if c:
                    match o.nametype:
                        case "Door":
                            logging.info(f"Collision between player and {o.name}")
                            if o.passthrough(self.items):
                                logging.info("Player has the key!")
                                self.objects.remove(o)
                                self.physics_engine.remove_generic_object(o)
                            else:
                                logging.debug(self.player.last_movement)

                        case "Item":
                            self.gather_items([o])

                        case "weapon":
                            logging.info("collided with weapon")

            if o.nametype == "NPC":
                o.display_textbox = self.display_textbox
                if o.get_rect().expand(20).collides(self.player.get_rect()):
                    # Don't move if the player is near.
                    o.stop_moving(self.player.x, self.player.y)
                    if arcade.key.E in self.newly_pressed_keys and self.textbox is None:
                        # Start a dialogue if we're close to the NPC.
                        o.turn_to_player(self.player.x, self.player.y)
                        o.dialogue()
                else:
                    o.resume_moving()

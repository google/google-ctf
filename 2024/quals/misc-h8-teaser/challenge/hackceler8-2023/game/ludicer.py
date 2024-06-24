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
from threading import Thread, Lock
import json
import logging
import os
import time

import arcade
import dill
import numpy as np
import xxhash

import constants
from components import textbox
from components.inventory import Inventory
from components.llm.llm import Llm
from components.enemy.enemy import Enemy
from components.switch import Switch
from components.magic_items import ItemCollection, Item
from engine import physics, logic
from engine.danmaku import DanmakuSystem
from engine.combat import CombatSystem
from engine.grenade import GrenadeSystem
from engine.map_switcher import MapSwitch
from engine.rng import RngSystem
from map_loading import maps
from map_loading.maps import GameMode
from engine.ludifier import Ludifier

from constants import PLAYER_MOVEMENT


class MagicItem(Enum):
    ITEM_PURPLE = "purple"


COLOR_LIST = [
    arcade.color.GREEN,
    arcade.color.RED,
    arcade.color.YELLOW,
]


class Ludicer:
    def __init__(self, net, is_server, debug=False, eager_level_load=True):
        self.mutex = Lock()
        self.net = net

        # persistent stuff
        self.items = []
        self.win_timestamp = 0
        self.tics = 0
        self.flag = None

        if not is_server and self.net is not None:
            self.setup_client()
        self.is_server = is_server
        self.rand_seed = None

        if debug:
            self.maps_dict = maps.load_debug()
        else:
            self.maps_dict = maps.load()

        # We keep a pristine copy to allow for resets
        self.original_maps_dict = copy(self.maps_dict)

        self.arena_mapping = {
            "spike_arena": "spike",
            "speed_arena": "speed",
            "logic_arena": "logic",
            "boss_arena": "boss",
            "danmaku_arena": "danmaku",
            "purple_arena": "cctv",
            "red_arena": "rusty",
            "violet_arena": "space",
            "orange_arena": "water"
        }

        self.scene_dict = {}
        if eager_level_load:
            for v in self.maps_dict.values():
                # A game has either a prerender or a scene
                if v.prerender is None and v.tiled_map not in self.scene_dict:
                    self.scene_dict[v.tiled_map] = arcade.Scene.from_tilemap(
                        v.tiled_map.to_arcade_tilemap())

        # variable stuff
        self.player = None
        self.player_last_base_position = None
        self.player_starting_position = {}

        # use this for solid, more/less static stuff
        self.objects = []
        self.global_match_items = None
        self.get_all_available_items()

        # use this for stuff that should never move
        self.static_objs = []

        # use this for more complex interactions
        self.dynamic_artifacts = []

        self.pkgs_from_server = []

        self.mouse_position = None
        self.current_color = arcade.color.GREEN

        self.next_map = None
        self.current_map = "base"
        self.tiled_map = None
        self.scene = None
        self.prerender = None
        self.map_switch = None
        self.textbox = None
        self.current_mode = None
        self.state_hash = None
        self.cheating_detected = False

        self.level_modifier = None

        self.inventory = Inventory(self, is_server=self.is_server)
        self.llm = Llm()
        self.rng_system = RngSystem()
        self.combat_system = None
        self.physics_engine = None
        self.logic_engine = None
        self.danmaku_system = None
        self.grenade_system = None

        self.boss = None
        self.unlocked_doors = set()

        self.boss_llm_exists = False
        self.boss_danmaku_exists = False
        self.boss_danmaku_win_time = 0
        self.boss_llm_win_time = 0

        self.prev_display_inventory = False
        self.display_inventory = False

        self.newly_pressed_keys = set()
        self.prev_pressed_keys = set()
        self.tracked_keys = {
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
            arcade.key.P,
            arcade.key.F,

            # NPC
            arcade.key.E,
            arcade.key.ENTER,

            # Weapons
            arcade.key.Q,
            arcade.key.SPACE,

            # Soul Grenade
            arcade.key.T,
        }
        self.raw_pressed_keys = set()
        self.pressed_keys = set()

        self.collect_coin_sound = arcade.load_sound(":resources:sounds/coin1.wav")
        self.jump_sound = arcade.load_sound(":resources:sounds/jump1.wav")

        self.setup()

    @property
    def won(self):
        # Game is won if the time is neither None nor 0
        return self.win_timestamp

    @won.setter
    def won(self, _value):
        if self.win_timestamp > 0:
            return
        self.win_timestamp = time.time()

    def get_flag(self, flag):
        self.flag = flag
        if self.is_server and self.net is not None:
            msg = json.dumps({"flag": flag}).encode()
            self.net.send_one(msg)

    def dump_state(self):
        h = ""
        for i in self.objects + self.static_objs + self.items + \
                 self.dynamic_artifacts + [self.player, self.rng_system]:
            h += i.hash
        h += xxhash.xxh64(str(self.tics)).hexdigest()
        self.state_hash = xxhash.xxh64(h.encode()).hexdigest()

    # This section needsto be hardcoded for each match
    def get_all_available_items(self):
        self.boss_danmaku_exists = True
        self.boss_llm_exists = True
        # Need to add variable items here
        its = [
            Item(None, name="key_violet", display_name="Violet key", color="violet",
                 wearable=False),
            Item(None, name="key_purple", display_name="Purple key", color="purple",
                 wearable=False),
            Item(None, name="key_orange", display_name="Orange key", color="orange",
                 wearable=False),
            Item(None, name="key_blue", display_name="Blue key", color="blue",
                 wearable=False),
            #Uncomment the one that is not needed
            Item(None, name="flag_danmaku", display_name="Danmaku flag",
                 wearable=False),
            Item(None, name="flag_llm", display_name="LLM flag",
                 wearable=False),
        ]

        for i in its:
            for ci in self.items:
                if ci.name == i.name:
                    i.collected_time = ci.collected_time

        ic = ItemCollection(its)
        if not ic.verify():
            logging.critical("Duplicate item found, game will exit")
            exit()
        self.global_match_items = ic

    def play_time_str(self) -> str:
        s = round(self.tics * constants.TICK_S)
        m = s // 60 % 60
        h = m // 60
        s %= 60
        m %= 60
        return "%d:%02d:%02d" % (h, m, s)

    def setup_client(self):
        self.pkgs_from_server = []

        def _process_server_pkgs():
            while True:
                msg = self.net.recv_one()
                with self.mutex:
                    self.pkgs_from_server.append(msg)

        Thread(target=_process_server_pkgs, daemon=True).start()

    def recv_from_server(self):
        with self.mutex:
            for msg in reversed(self.pkgs_from_server):
                logging.critical(f"Recv new msg {msg}")
                try:
                    d = json.loads(msg.decode())
                except Exception as e:
                    logging.critical(f"Failed to decode message: {e}")
                    raise
                if "llm_resp" in d:
                    resp = d["llm_resp"]
                    guessed = d.get("codeword_guessed", False)
                    logging.info(f"Got LLM response from server: \"{resp}\"")
                    self.llm.last_msg = (resp, guessed)
                if "u_cheat" in d:
                    self.cheating_detected = True
                if "flag" in d:
                    self.flag = d["flag"]
            self.pkgs_from_server = []

    def reset_to_main_map(self):
        self.player.reset_movements()
        self.switch_maps("base")

    def setup(self):
        self.scene = None
        self.prerender = None
        self.objects = []
        self.dynamic_artifacts = []
        self.static_objs = []

        self.combat_system = None
        self.danmaku_system = None
        self.grenade_system = None
        self.physics_engine = None
        self.logic_engine = None
        self.level_modifier = None
        self.current_mode = self.maps_dict[self.current_map].game_mode

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
        self.tiled_map = self.maps_dict[self.current_map].tiled_map
        logging.debug(
            f"Loaded map {self.current_map} with {self.tiled_map.size},  (tile width:{self.tiled_map.tile_size}, total size: {self.tiled_map.map_size_pixels})")

        if False and self.tiled_map not in self.scene_dict:
            self.scene_dict[self.current_map] = arcade.Scene.from_tilemap(
                self.tiled_map.to_arcade_tilemap())
        self.scene = self.scene_dict.get(self.tiled_map, None)
        self.prerender = self.maps_dict[self.current_map].prerender

        for o in self.tiled_map.dynamic_artifacts:
            o.reset()
            self.dynamic_artifacts.append(o)

        logging.info(f"Items before parsing: {self.items}")
        for o in self.tiled_map.objs:
            o.reset()

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
                self.player.game = self
                self.player.base_x_speed = PLAYER_MOVEMENT
                self.player.base_y_speed = PLAYER_MOVEMENT
                self.player.regen()
                self.player.modify(self.items)

            elif o.nametype == "Item":
                self.objects.append(o)

            else:
                self.objects.append(o)
                if o.nametype == "Boss":
                    self.boss = o
                    if self.won:
                        o.destructing = True
                        o.destruct_timer = 0
                        o.dead = True

        targets = [o for o in self.objects if o.nametype == "Enemy"]
        self.combat_system = CombatSystem(self, self.tiled_map.weapons, targets=targets)
        if self.current_map in {"cctv"}:
            self.grenade_system = GrenadeSystem(self, targets=targets)

        if self.current_map == "danmaku":
            self.danmaku_system = DanmakuSystem(self.player, self.boss,
                                                is_server=self.is_server)

        self.static_objs = self.tiled_map.static_objs.copy()
        for o in self.static_objs:
            o.reset()
        for o in self.tiled_map.moving_platforms:
            o.reset()

        self.physics_engine = physics.PhysicsEngine(
            platformer_rules=(self.current_mode == GameMode.MODE_PLATFORMER),
            objects=[self.player] + self.objects + self.dynamic_artifacts,
            qt=self.tiled_map.qt, obj_map=self.tiled_map.obj_map,
            static_objects=self.static_objs)
        self.physics_engine.game = self
        self.physics_engine.env_tiles = self.tiled_map.env_tiles
        self.physics_engine.moving_platforms = self.tiled_map.moving_platforms

        self.logic_engine = logic.LogicEngine(self.tiled_map.logic_map)

        logging.debug("Scroller setup complete")

    def setup_platformer(self):
        self.setup_scroller()
        self.player.base_y_speed = 320
        self.level_modifier = Ludifier(self.tiled_map)

    def switch_maps(self, new_map):
        if (new_map == "boss" or new_map == "danmaku") and len(self.unlocked_doors) < 4:
            logging.warning(f"Boss area not unlocked yet, r u cheating?")
            return
        if self.current_map == "base" and self.current_map != new_map:
            # Bump back a little bit to avoid floating-point error.
            dir_x = np.sign(self.player.prev_x - self.player.x)
            dir_y = np.sign(self.player.prev_y - self.player.y)
            back_x = self.player.prev_x + dir_x * 3
            back_y = self.player.prev_y + dir_y * 3
            self.player_last_base_position = (back_x, back_y)

        self.current_map = new_map
        logging.debug(self.current_map)

        def switch():
            self.player.weapons = []
            self.setup()

        def cleanup():
            self.map_switch = None

        self.map_switch = MapSwitch(switch, cleanup)

    def display_textbox(self, text: str, choices: list[str] = None,
                        free_text: bool = False, from_llm: bool = False,
                        process_fun=None):
        if self.textbox is not None:  # Already displaying
            return

        def cleanup():
            self.textbox = None
            # Avoid opening the textbox immediately again
            if arcade.key.E in self.newly_pressed_keys:
                self.newly_pressed_keys.remove(arcade.key.E)

        self.textbox = textbox.Textbox(self, text, cleanup, choices, free_text,
                                       from_llm, process_fun)

    def query_llm(self, text):
        serverless_client = self.net is None
        if not self.is_server and not serverless_client:
            logging.error("Called query_llm on client, should only be used on server")
            return

        def _query_llm(text):
            resp, codeword_guessed = self.llm.chat(text)
            with self.mutex:
                self.llm.last_msg = (resp, codeword_guessed)
            if not serverless_client:
                logging.info(f"Sending LLM response to client: \"{resp}\"")
                msg = json.dumps({"llm_resp": resp,
                                  "codeword_guessed": codeword_guessed}).encode()
                self.net.send_one(msg)

        Thread(target=_query_llm, args=(text,), daemon=True).start()

    def objects_frozen(self):
        return self.map_switch is not None or self.textbox is not None

    def send_game_info(self):
        if self.is_server or self.net is None:
            return
        with self.mutex:
            llm_ack = self.llm.last_msg is not None
            self.llm.last_msg = None
        logging.debug(f"{self.tics} : {self.raw_pressed_keys}")
        msg = {"tics": self.tics, "state": self.state_hash,
               "keys": list(self.raw_pressed_keys),
               "text_input": self.get_text_input(),
               "llm_ack": llm_ack}
        if self.rand_seed != 0:
            msg["seed"] = self.rand_seed
            self.rand_seed = 0
        msg = json.dumps(msg).encode()
        self.net.send_one(msg)

    def get_text_input(self):
        if self.is_server:
            logging.error(
                "Called get_text_input on server, should only be used on client")
            return
        if self.textbox is None or not self.textbox.text_input_appeared:
            return None
        return self.textbox.text_input.text

    def set_text_input(self, text):
        if not self.is_server:
            logging.error(
                "Called set_text_input on client, should only be used on server")
            return
        if self.textbox is None or not self.textbox.text_input_appeared:
            return
        self.textbox.text_input.text = text

    def tick(self):
        self.init_random()
        self.rng_system.tick(self.raw_pressed_keys, self.tics)

        self.pressed_keys = self.tracked_keys & self.raw_pressed_keys
        self.newly_pressed_keys = self.pressed_keys.difference(self.prev_pressed_keys)
        self.prev_pressed_keys = self.pressed_keys.copy()

        if self.cheating_detected or self.won:
            return self.send_game_info()

        self.tics += 1
        if not self.is_server and self.net is not None:
            self.recv_from_server()

        if self.flag is not None:
            return self.send_game_info()

        self.dump_state()
        self.prev_display_inventory = self.display_inventory
        if arcade.key.P in self.newly_pressed_keys and self.textbox is None:
            self.display_inventory = not self.display_inventory
        if self.display_inventory:
            self.inventory.tick(self.newly_pressed_keys)

        if self.display_inventory:
            return self.send_game_info()
        if self.map_switch is not None:
            self.map_switch.tick()
        if self.textbox is not None:
            with self.mutex:
                if (self.llm.last_msg is not None and
                        # On the server display the message once the client ACKd it.
                        (not self.is_server or self.llm.ack_recvd)):
                    text, guessed = self.llm.last_msg
                    self.llm.ack_recvd = False
                    if self.net is None:
                        # Clear the message here since send_game_info is not called.
                        self.llm.last_msg = None
                    self.textbox.set_text_from_server(text)
                    if guessed:
                        for o in self.objects:
                            if o.nametype == "Boss":
                                o.codeword_guessed = True
            self.textbox.tick(self.newly_pressed_keys)
            # Animate the boss even when there's a dialogue.
            for o in self.objects:
                if o.nametype == "Boss":
                    o.sprite.tick()

        if self.objects_frozen():
            return self.send_game_info()

        if arcade.key.ESCAPE in self.newly_pressed_keys:
            self.reset_to_main_map()
        elif arcade.key.R in self.newly_pressed_keys:
            self.reset_current_level()

        self.check_modifier_proximities()
        self.check_proximities()
        for ac in self.combat_system.active_projectiles:
            ac.tick()
        self.combat_system.tick(self.pressed_keys, self.newly_pressed_keys, self.tics)
        if self.grenade_system:
            self.grenade_system.tick(self.newly_pressed_keys)
        if self.danmaku_system:
            self.danmaku_system.tick(self.pressed_keys)

        for o in list(self.objects):
            o.game = self
            o.tick()
            if o.nametype == "Boss" and o.dead:
                self.objects.remove(o)
                self.physics_engine.remove_generic_object(o)
                self.tiled_map.objs.remove(o)
                self.gather_items([o.yield_item()])
                match o.version:
                    case "lambda":
                        self.boss_danmaku_win_time = time.time()
                    case "alpha":
                        self.boss_llm_win_time = time.time()
        if self.global_match_items.won_all():
            logging.info(f"Completed the game! Play time: %s" % self.play_time_str())
            self.won = True
        Enemy.respawn()
        Enemy.check_control_inversion(self)
        Switch.check_all_pressed(self)

        if self.player is not None:
            self.player.tick(self.pressed_keys,
                             self.newly_pressed_keys,
                             reset_speed=(self.current_mode == GameMode.MODE_SCROLLER))

        self.physics_engine.tick()
        self.gather_items(self.physics_engine.tmp_loot)
        self.physics_engine.tmp_loot = []
        self.logic_engine.tick()

        if self.physics_engine.exit_on_next:
            self.switch_maps("base")

        if self.level_modifier is not None:
            new_object = self.level_modifier.tick()
            if new_object is not None:
                self.static_objs.append(new_object)

        return self.send_game_info()

    def init_random(self):
        if not self.is_server:
            if self.rand_seed is None:
                self.rand_seed = int.from_bytes(os.urandom(4), byteorder='big')
                self.rng_system.seed(self.rand_seed)
        # Sync seed with client on startup.
        elif self.rand_seed is not None and self.tics == 0:
            self.rng_system.seed(self.rand_seed)
            self.rand_seed = None

    def gather_items(self, items):
        for i in items:
            # Make sure we record the time of collection
            self.global_match_items.mark_collected(i.name)
            # i.collected_time = time.time()
            self.items.append(i)
            if i.wearable:
                self.player.wear_item(i)
            if i in self.objects:
                logging.debug("Player received a new item!")
                self.objects.remove(i)
                self.tiled_map.objs.remove(i)
        self.player.modify(self.items)

    def check_boss_area_unlocked(self):
        if len(self.unlocked_doors) >= 4:
            logging.info("Player unblocked boss area!")
        else:
            return
        for o in self.objects:
            if o.nametype == "BossGate":
                o.sprite.set_animation("on")

    def check_modifier_proximities(self):
        if self.player.dead:
            return
        for o in self.objects + self.dynamic_artifacts:
            if o.modifier is not None:
                c, _ = o.collides(self.player)
                if c:
                    self.player.apply_modifier(o.modifier, 0)
                    logging.info(f"apply {o.name} {self.tics}")
                    continue
                current_distance = o.proximity(self.player)
                if current_distance < o.modifier.min_distance:
                    self.player.apply_modifier(o.modifier, current_distance)

    def check_proximities(self):
        if self.player.dead:
            return
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
                        self.dump_state()
                        self.switch_maps("base")
                        return

                    case "Portal":
                        if not o.deduct_usage():
                            logging.info(
                                "Punished due to exceeding Portal usage limit.")
                            self.player.dead = True

                        logging.info(f"Portal {o.name} teleports to "
                                     f"({o.dest.x}, {o.dest.y}) at tick "
                                     f"{self.tics}")
                        self.player.place_at(o.dest.x, o.dest.y)
                        self.player.set_speed(o.x_speed, o.y_speed)
                        self.player.in_the_air = True
                        return

        for o in self.objects:
            if o.blocking:
                if o.get_rect().expand(2).collides(self.player.get_rect()):
                    match o.nametype:
                        case "Door":
                            logging.info(f"Collision between player and {o.name}")
                            arcade.play_sound(self.jump_sound)
                            if o.passthrough(self.items):
                                logging.info("Player has the key!")
                                self.unlocked_doors.add(o.unlocker)
                                self.objects.remove(o)
                                self.physics_engine.remove_generic_object(o)
                                self.check_boss_area_unlocked()
                            else:
                                logging.debug(self.player.last_movement)

            if o.nametype == "NPC" or o.nametype == "Boss":
                o.display_textbox = self.display_textbox
                if o.get_rect().expand(20).collides(self.player.get_rect()):
                    if o.nametype == "NPC":
                        # Don't move if the player is near.
                        o.stop_moving(self.player.x, self.player.y)
                    if self.danmaku_system is None and arcade.key.E in \
                            self.newly_pressed_keys and self.textbox is None:
                        # Start a dialogue if we're close.
                        if o.nametype == "NPC":
                            o.turn_to_player(self.player.x, self.player.y)
                        o.dialogue()
                elif o.nametype == "NPC":
                    o.resume_moving()

            elif o.nametype == "Toggle":
                c, _ = o.collides(self.player)
                if c and arcade.key.E in self.newly_pressed_keys:
                    o.interact()

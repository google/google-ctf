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

from copy import copy
from enum import Enum
import importlib
import json
import logging
import os
import pathlib
import re
import sys
from threading import Lock, Thread
import time
from typing import Optional

from typing import Optional

from game import constants
from game.components import textbox, player
from game.components.enemy.enemy import Enemy
from game.components.flags import load_match_flags
from game.components.inventory import Inventory
from game.components.items import Item, check_item_loaded
from game.components.player import Player
from game.engine import physics
from game.engine.arcade_system.arcade_system import ArcadeSystem
from game.engine.generics import GenericObject
from game.engine import gfx
from game.engine.keys import Keys
from game.engine.painting import PaintingSystem
from game.engine.projectile import ProjectileSystem
from game.engine.venatizer import Venatizer
from game.engine.screen_fader import ScreenFader
from game.engine.save_file import SaveFile, apply_save_state
from game.map import maps, tilemap
import xxhash


class MagicItem(Enum):
    ITEM_PURPLE = "purple"


class Venator:
    def __init__(self, net, is_server: bool):
        self.mutex = Lock()
        self.net = net

        # persistent stuff
        self.items: list[Item] = []
        self.match_flags = load_match_flags()
        self.win_timestamp = 0
        self.tics = 0
        self.ready = True

        if not is_server and self.net is not None:
            self.ready = False
            self.setup_client()
        self.is_server: bool = is_server
        self.rand_seed = None

        self.save_file = SaveFile()

        if is_server:
            self.load_file = "save_state"
            if self.load_file != "":
                try:
                    apply_save_state(self.save_file.load(), self)
                except Exception as e:
                    logging.critical(f"Unable to read file {self.load_file}: {e}")

        self.maps_dict = maps.load()

        # We keep a pristine copy to allow for resets
        self.original_maps_dict = copy(self.maps_dict)

        self.scene_dict: dict[tilemap.TileMap, gfx.TileMap] = {}
        if not self.is_server:
            for v in self.maps_dict.values():
                # A game has either a prerender or a scene
                if not v.has_prerender() and v.tiled_map not in self.scene_dict:
                    self.scene_dict[v.tiled_map] = v.tiled_map.get_arcade_scene()

        # variable stuff
        self.player: Optional[Player] = None
        self.player_starting_position: dict[str, (int, int)] = {}

        self.objects: list[GenericObject] = []

        self.next_map = None
        self.current_map = "base"
        self.exit_on_next = False
        self.tiled_map: Optional[tilemap.TileMap] = None
        self.scene: Optional[gfx.TileMap] = None
        self.prerender: Optional[gfx.SpriteLayer] = None
        self.screen_fader: Optional[ScreenFader] = None
        self.textbox: Optional[textbox.Textbox] = None
        self.state_hash = None
        self.cheating_detected = False

        self.module_reloading = False

        self.level_modifier = None

        self.inventory = Inventory(self, is_server=self.is_server)
        self.painting_system: Optional[PaintingSystem] = None
        self.painting_enabled: bool = False
        self.projectile_system: Optional[ProjectileSystem] = None
        self.arcade_system: Optional[ArcadeSystem] = None
        self.physics_engine: Optional[physics.PhysicsEngine] = None

        self.boss: Optional[GenericObject] = None

        self.prev_display_inventory = False
        self.display_inventory = False

        self.save_cooldown = False
        self.save_cooldown_timer = 0

        self.newly_pressed_keys = set()
        self.prev_pressed_keys = set()
        self.tracked_keys = {
            # Movement
            Keys.W,
            Keys.A,
            Keys.S,
            Keys.D,
            # running
            Keys.LSHIFT,
            Keys.LCTRL,
            # Menu
            Keys.ESCAPE,
            Keys.P,
            Keys.R,
            # NPC
            Keys.E,
            Keys.ENTER,
            # Weapons
            Keys.Q,
            Keys.SPACE,
        }
        self.raw_pressed_keys: set[Keys] = set()
        self.pressed_keys = set()

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

    def dump_state(self):
        h = ""
        for i in (
                self.objects
                + self.items
                + [self.player]
        ):
            h += i.hash
        h += xxhash.xxh64(str(self.tics)).hexdigest()
        self.state_hash = xxhash.xxh64(h.encode()).hexdigest()

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
                if b"save_state" in msg:
                    logging.info(msg)
                    try:
                        _save_state = json.loads(msg.decode())["save_state"]
                    except Exception as e:
                        logging.critical(
                            f"Failed to parse save state from server: {e}")
                        continue
                    apply_save_state(_save_state, self)
                    logging.info("Loaded save state from server")
                    with self.mutex:
                        self.ready = True
                with self.mutex:
                    self.pkgs_from_server.append(msg)

        Thread(target=_process_server_pkgs, daemon=True).start()

    def recv_from_server(self):
        with self.mutex:
            for msg in reversed(self.pkgs_from_server):
                try:
                    msg = json.loads(msg.decode())
                except Exception as e:
                    logging.critical(f"Failed to decode message: {e}")
                    raise
                if "chat_text" in msg:
                    if self.textbox is not None and self.textbox.from_server:
                        text = msg["chat_text"]
                        logging.info(f"Got chat message from server: \"{text}\"")
                        choices = msg["chat_choices"]
                        if choices is None:
                            choices = []
                        free_text = msg["chat_free_text"]
                        self.textbox.set_text_from_server(text, choices, free_text)
                if "u_cheat" in msg:
                    self.cheating_detected = True
                if "module_reload" in msg:
                    patchs = msg["module_reload"]
                    self.client_reload_module(patchs)
            self.pkgs_from_server = []

    def reset_to_main_map(self):
        self.switch_maps("base")

    def load_map(self, map_name: str):
        if map_name in self.maps_dict:
            logging.debug(f"loading map {self.current_map}")
            self.switch_maps(map_name)
            return

        logging.warning(
            f"{map_name} is not associated with any maps, r u cheating?"
        )

    def setup(self):
        self.scene = None
        self.prerender = None
        self.objects = []

        self.painting_system = None
        self.projectile_system = None
        self.physics_engine = None
        self.level_modifier = None
        self.textbox = None

        self.setup_map()

    def deep_reset_level(self, level_name: str):
        if level_name not in self.maps_dict:
            logging.critical(f"Unknown map {level_name}")
            return
        self.maps_dict[level_name] = self.original_maps_dict[level_name]

    def reset_current_level(self):
        self.deep_reset_level(self.current_map)
        self.switch_maps(self.current_map)

    def setup_map(self):
        self.tiled_map = self.maps_dict[self.current_map].tiled_map
        logging.debug(
            f"Loaded map {self.current_map} with {self.tiled_map.size},  (tile"
            f" width:{self.tiled_map.tile_size.width}, total size:"
            f" {self.tiled_map.map_size_pixels})"
        )

        if not self.is_server:
            self.scene = self.scene_dict.get(self.tiled_map, None)
            self.prerender = self.maps_dict[self.current_map].prerender()
        self.boss = None

        logging.info(f"Items before parsing: {self.items}")
        for o in self.tiled_map.objects:
            o.reset()

            if o.nametype == "Player":
                assert isinstance(o, Player)
                logging.debug("Have player")
                if (
                        self.current_map == "base"
                        and o.last_ground_pos is not None
                ):
                    o.place_at(o.last_ground_pos.x, o.last_ground_pos.y)
                    o.in_the_air = False
                elif self.current_map in self.player_starting_position:
                    x, y = self.player_starting_position[self.current_map]
                    o.place_at(x, y)
                else:
                    self.player_starting_position[self.current_map] = (o.x, o.y)
                self.player = o
                self.player.game = self
                self.player.modify(self.items)

            elif o.nametype == "Item":
                if not check_item_loaded(self.items, o):
                    self.objects.append(o)
                else:
                    logging.info(f"Duplicate object {o.nametype, o.name} detected")

            else:
                self.objects.append(o)
                if o.nametype == "NPC" and o.name.startswith("trapped_"):
                    if self.match_flags.obtained(o.name[len("trapped_"):-len("_npc")]):
                        o.freed = True
                elif o.nametype == "Boss":
                    self.boss = o
                    o.game = self
                    o.reload_module()
                    if self.match_flags.obtained(o.name):
                        o.destructing = True
                        o.destruct_timer = 0
                        o.dead = True

        targets = [o for o in self.objects if o.nametype == "Enemy" or o.name == "fighting_boss"]
        self.projectile_system = ProjectileSystem(
            self, self.tiled_map.weapons, targets=targets
        )

        self.physics_engine = physics.PhysicsEngine(self, objects=[self.player] + self.objects)
        self.physics_engine.env_tiles = self.tiled_map.env_tiles
        self.level_modifier = Venatizer(self.tiled_map)

    def switch_maps(self, new_map):
        curr_map = self.current_map
        self.current_map = new_map
        logging.debug(self.current_map)

        def switch():
            self.player.weapons = []
            if new_map == "base" and curr_map == "base":
                # Put back player to starting pos.
                self.player.last_ground_pos = None
            self.setup()

        def cleanup():
            self.screen_fader = None

        self.screen_fader = ScreenFader(switch, cleanup)

    def display_textbox(
            self,
            text: str = "",
            choices: list[str] = None,
            free_text: bool = False,
            process_fun=None,
            from_server=False,
            text_for_success="",
            success_fun=None,
    ):
        if self.textbox is not None:  # Already displaying
            return

        def cleanup():
            self.textbox = None
            # Avoid opening the textbox immediately again
            if Keys.E in self.newly_pressed_keys:
                self.newly_pressed_keys.remove(Keys.E)
            self.player.immobilized = False

        self.textbox = textbox.Textbox(
            self, text, cleanup, choices, free_text, process_fun, from_server,
            text_for_success, success_fun
        )
        self.player.immobilized = True
        if self.is_server:
            logging.info(f"Sending chat message to client: \"{text}\"")
            msg = json.dumps({"chat_text": text, "chat_choices": choices,
                              "chat_free_text": free_text}).encode()
            self.net.send_one(msg)

    def objects_frozen(self):
        return self.screen_fader is not None or self.arcade_system is not None

    def send_game_info(self):
        if self.is_server or self.net is None:
            return
        logging.debug(f"{self.tics} : {self.raw_pressed_keys}")
        msg = {
            "tics": self.tics,
            "state": self.state_hash,
            "keys": [i.serialized for i in self.raw_pressed_keys],
            "text_input": self.get_text_input(),
        }
        if self.rand_seed != 0:
            msg["seed"] = self.rand_seed
            self.rand_seed = 0

        msg = json.dumps(msg).encode()
        self.net.send_one(msg)

    def get_text_input(self) -> Optional[str]:
        if self.is_server:
            logging.error(
                "Called get_text_input on server, should only be used on client"
            )
            return
        if self.textbox is None or not self.textbox.text_input_appeared:
            return None
        return self.textbox.text_input.text

    def set_text_input(self, text: str):
        if not self.is_server:
            logging.error(
                "Called set_text_input on client, should only be used on server"
            )
            return
        if self.textbox is None or not self.textbox.text_input_appeared:
            return
        self.textbox.text_input.text = text

    def init_arcade_system(self):
        def init():
            try:
                self.arcade_system = ArcadeSystem(self)
            except Exception as e:
                logging.critical(f"Failed to start arcade system: {e}")
                raise

        def cleanup():
            self.screen_fader = None

        self.screen_fader = ScreenFader(init, cleanup)

    def close_arcade_system(self):
        def close():
            self.arcade_system = None

        def cleanup():
            self.screen_fader = None

        self.arcade_system.close()
        self.screen_fader = ScreenFader(close, cleanup)

    def _save(self):
        if self.is_server and not self.save_cooldown and not self.player.dead:
            logging.info(f"Saving state, items: {self.items}")
            self.save_file.save(self)
            self.save_cooldown = True
            self.save_cooldown_timer = constants.SAVE_COOLDOWN

        if self.save_cooldown_timer > 0:
            self.save_cooldown_timer -= 1
        else:
            self.save_cooldown = False

    def tick(self):
        if not self.ready:
            return

        if self.module_reloading:
            assert not self.is_server and self.net is not None
            self.recv_from_server()
            return

        self.pressed_keys = self.tracked_keys & self.raw_pressed_keys
        self.newly_pressed_keys = self.pressed_keys.difference(
            self.prev_pressed_keys
        )
        self.prev_pressed_keys = self.pressed_keys.copy()

        self._save()

        if self.cheating_detected or self.won:
            self.send_game_info()
            return

        if self.arcade_system is not None and self.screen_fader is None:
            self.arcade_system.tick()

        self.tics += 1
        if self.player.health <= 0:
            self.player.dead = True
        if not self.is_server and self.net is not None:
            self.recv_from_server()
        self.dump_state()
        self.prev_display_inventory = self.display_inventory
        if Keys.P in self.newly_pressed_keys and self.textbox is None:
            self.display_inventory = not self.display_inventory
        if self.display_inventory:
            self.inventory.tick(self.newly_pressed_keys)
        if self.display_inventory:
            self.send_game_info()
            return
        if self.screen_fader is not None:
            self.screen_fader.tick()
        if self.textbox is not None:
            self.textbox.tick(self.newly_pressed_keys)
            # Animate the boss even when there's a dialogue.
            for o in self.objects:
                if o.nametype == "Boss":
                    o.sprite.tick()

        for o in list(self.objects):
            if (o.nametype == "NPC" and o.freed) or (o.nametype == "Boss" and o.dead):
                self.objects.remove(o)
                self.physics_engine.remove_generic_object(o)
                self.tiled_map.objects.remove(o)

        if self.objects_frozen():
            self.send_game_info()
            return

        if not self.player.immobilized:
            if Keys.ESCAPE in self.newly_pressed_keys:
                self.reset_to_main_map()
            elif Keys.R in self.newly_pressed_keys:
                self.reset_current_level()

        if self.painting_system is not None:
            self.painting_system.tick(self.newly_pressed_keys)

        self.check_modifier_proximities()

        for o in list(self.objects):
            o.game = self
            o.tick()

        for projectile in self.projectile_system.active_projectiles:
            projectile.tick()
        self.projectile_system.tick(
            self.pressed_keys, self.newly_pressed_keys, self.tics
        )

        if self.match_flags.beat_bosses():
            logging.info(f"Completed the game! Play time: {self.play_time_str()}")
            self.won = True
            self.save_file.save(self)

        Enemy.respawn()

        if self.player is not None:
            self.player.tick(
                self.pressed_keys,
                self.newly_pressed_keys,
            )

        self.physics_engine.tick()

        if self.exit_on_next:
            self.exit_on_next = False
            self.switch_maps("base")
        elif self.current_map == "dialogue_boss" and self.player.x1 < -5:
            self.load_map("base")


        if self.level_modifier is not None:
            self.level_modifier.tick()

        self.send_game_info()

    def gather_item(self, item: Item):
        self.gather_items([item])

    def gather_items(self, items: list[Item]):
        for i in items:
            # Make sure we record the time of collection
            if i.collected_time == 0:
                i.collected_time = time.time()
            self.items.append(i)
            if i in self.objects:
                logging.debug("Player received a new item!")
                self.objects.remove(i)
                self.tiled_map.objects.remove(i)
            self.physics_engine.remove_generic_object(i)
        self.player.modify(self.items)

        if not self.player.dead and len(items) > 0:
            # Save the current progress as soon as an item has been collected
            logging.info("Saving on account of new item collected")
            self.save_file.save(self)

    def free_npc(self, npc, stars: int):
        def free_npc():
            npc.freed = True
            prev_unlocked_boss = self.match_flags.unlocked_boss()
            self.match_flags.obtain_flag(
                npc.name.removeprefix("trapped_").removesuffix("_npc"))
            logging.info(f"Got {stars} stars, total: {self.match_flags.stars()}")
            self.save_file.save(self)
            if not prev_unlocked_boss and self.match_flags.unlocked_boss():
                logging.info(f"Unlocked boss!")
                # Put player back to near the boss gate.
                for o in self.maps_dict["base"].tiled_map.objects:
                    if o.nametype == "Player":
                        o.last_ground_pos = None
                        break

        def cleanup():
            self.screen_fader = None

        self.screen_fader = ScreenFader(free_npc, cleanup)

    def check_modifier_proximities(self):
        if self.player.dead:
            return
        for o in self.objects:
            if o.modifier is not None:
                if o.collides(self.player):
                    self.player.apply_modifier(o.modifier, 0)
                    logging.info(f"apply {o.name} {self.tics}")
                    continue
                current_distance = o.proximity(self.player)
                if current_distance < o.modifier.min_distance:
                    self.player.apply_modifier(o.modifier, current_distance)

    # Path should be the path of module in Python, such as game.components.boss.implementation
    def server_send_reload_module(self, paths: list[str]):
        if not self.is_server or self.net is None:
            return
        result = {}
        # Find code for each module
        for path in paths:
            if not path in sys.modules:
                continue
            logging.info(f"Add reloading module {path}")
            # Get file path from module information
            file_path = sys.modules[path].__file__
            # Read file and store into result
            with open(file_path, "r") as file:
                path = path.removesuffix("_server")
                result[path] = file.read()
        logging.info(f"Sending module reload message to client with {len(result)} modules.")
        msg = json.dumps({"module_reload": result}).encode()
        self.net.send_one(msg)

    def client_start_waiting_reload_module(self):
        if self.is_server or self.net is None:
            return
        logging.info(f"Waiting for reloading module, game paused.")
        self.module_reloading = True

    def get_module_version(self, code: str) -> int:
        # Use a regular expression to find the pattern
        # Match digits after the pattern
        version_pattern = r"VERSION_NUMBER=(\d+)"
        match = re.search(version_pattern, code)
        if match:
            version_number = match.group(1)
            return int(version_number)
        return -1

    def client_reload_module(self, patchs: dict[str, str]):
        logging.info(f"Handle reload message, reload modules.")
        root_dir = os.path.dirname(sys.modules["__main__"].__file__)
        for path in patchs:
            if not path in sys.modules:
                logging.info(f'Package {path} has not been loaded yet.')
                continue
            # Combine paths
            file_path = root_dir
            for name in path.split("."):
                file_path = os.path.join(file_path, name)
            file_path += ".py"
            # Check file, if this is not an existing file, skip
            if not pathlib.Path(file_path).is_file():
                logging.warning(f'{file_path} does not exist.')
                continue
            # Version
            current_version = -1
            with open(file_path, 'r') as file:
                current_version = self.get_module_version(file.read())
            # Content of the new code
            content = patchs[path]
            # Version
            new_version = self.get_module_version(content)
            if new_version <= current_version:
                if new_version == current_version:
                    logging.info(f'{file_path} version is same as the incoming module.')
                else:
                    logging.info(f'{file_path} version is newer than the incoming module.')
                continue
            # Replace file
            with open(file_path, "w") as file:
                file.write(content)
            # Reload
            importlib.reload(sys.modules[path])
            logging.info(f"{path} reloaded.")
        self.module_reloading = False


    def set_paint_mode(self, enabled: bool):
        if self.painting_system is None:
            self.painting_system = PaintingSystem(self)
        self.painting_enabled = enabled

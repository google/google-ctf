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

import logging
from typing import Optional
import imgui
import os
import moderngl_window as mglw
import json

from game import constants
from game.engine import gfx
from game.engine.keys import Keys
from game.venator import Venator, EndpointType
from game.components.boss.bg import BossBG
from game.engine.save_file import apply_save_state

SCREEN_TITLE = "Hackceler8-24"

class Hackceler8(gfx.Window):
    window_size = (constants.SCREEN_WIDTH, constants.SCREEN_HEIGHT)
    title = SCREEN_TITLE

    def __init__(self, net=None, is_observer=False, **kwargs):
        super().__init__(**kwargs)
        self.heart = gfx.GuiImage.load(self, "resources/objects/heart.png")
        self.star = gfx.GuiImage.load(self, "resources/objects/star.png")
        self.stamina = gfx.GuiImage.load(self, "resources/objects/stamina.png")

        self.boss_bg = None

        self.net = net
        self.game: Optional[Venator] = None

        self.main_layer = gfx.CombinedLayer()

        self.camera = gfx.Camera(self.window_size[0], self.window_size[1])
        self.gui_camera = gfx.Camera(self.window_size[0], self.window_size[1])  # For screen space stationary objects.

        self.loading_screen_timer = 10
        self.is_observer = is_observer

    def setup_game(self):
        self.game = Venator(self.net if not self.is_observer else None, endpoint_type=EndpointType.SPECTATOR if self.is_observer else EndpointType.CLIENT)

    # Do not resize anything. This way the regular camera will scale, and gui is drawn separately anyway.
    def on_resize(self, width, height):
        pass

    def _center_camera_to_player(self):
        if not self.game.ready or not self.game.map_loaded:
            return

        screen_center_x = self.game.player.x - (self.camera.viewport_width / 2)
        screen_center_y = self.game.player.y - (self.camera.viewport_height / 2)

        # Don't let camera travel past 0
        screen_center_x = max(screen_center_x, 0)
        screen_center_y = max(screen_center_y, 0)

        # additional controls to avoid showing around the map
        max_screen_center_x = (
                self.game.tiled_map.map_size_pixels.width - self.camera.viewport_width
        )
        max_screen_center_y = (
                self.game.tiled_map.map_size_pixels.height - self.camera.viewport_height
        )
        screen_center_x = min(screen_center_x, max_screen_center_x)
        screen_center_y = min(screen_center_y, max_screen_center_y)

        player_centered = screen_center_x, screen_center_y
        self.camera.move_to(player_centered)

    def draw(self):
        if self.game is None:
            mglw.ContextRefs.WINDOW.set_icon(os.path.abspath("resources/character/32bit/main32.PNG"))
            self.wnd.ctx.clear(color=(0, 0.5, 0, 1))
            gfx.draw_txt("loading", gfx.FONT_PIXEL[60], "Loading game...",
                         240, constants.SCREEN_HEIGHT/2 - 30, color=(164/255, 198/255, 57/255))
            return
        with self.game.mutex:
            if not self.game.ready or not self.game.map_loaded:
                mglw.ContextRefs.WINDOW.set_icon(os.path.abspath("resources/character/32bit/main32.PNG"))
                self.wnd.ctx.clear(color=(0, 0, 0, 0))
                gfx.draw_txt("waiting", gfx.FONT_PIXEL[40], "No player connected",
                             120, constants.SCREEN_HEIGHT/2 - 30, color=(164/255, 198/255, 57/255))
                return
        self.wnd.ctx.clear(color=(0, 0, 0, 1))

        if self.game.arcade_system is not None:
            self.game.arcade_system.draw()
            if self.game.screen_fader is not None:
                self.game.screen_fader.draw()
            # Arcade system covers the entire screen.
            return

        self.camera.update()
        self.camera.use()

        gfx.DEFAULT_ATLAS.maybe_build()
        if self.boss_bg is not None:
            self.boss_bg.draw()
        else:
            if self.game.prerender is None:
                self.game.scene.draw()
            else:
                self.game.prerender.draw_all_cached()

        self.main_layer.add_many(o.get_draw_info() for o in self.game.tiled_map.env_tiles)
        self.main_layer.draw(); self.main_layer.clear()

        self.main_layer.add_many(o.get_draw_info() for o in self.game.objects if not o.render_above_player)
        self.main_layer.draw(); self.main_layer.clear()

        if self.game.painting_system is not None:
            self.game.painting_system.draw()

        self.game.projectile_system.draw()

        if self.game.player is not None:
            p = self.game.player.get_draw_info()
            self.main_layer.add_many(p)
            self.main_layer.draw()
            self.main_layer.clear()

        self.main_layer.add_many(o.get_draw_info() for o in self.game.objects if o.render_above_player)
        self.main_layer.draw(); self.main_layer.clear()

        self.gui_camera.update()
        self.gui_camera.use()

        if self.game.boss is not None:
            self.game.boss.draw_gui()

        if self._white_text():
            imgui.push_style_color(imgui.COLOR_TEXT, 1,1,1,1)
        else:
            imgui.push_style_color(imgui.COLOR_TEXT, 0,0,0,1)

        gfx.draw_img("health", self.heart, 30, -80)
        gfx.draw_txt("health", gfx.FONT_PIXEL[30], ":%.02f" % self.game.player.health,
                     90, -75)
        gfx.draw_img("stars", self.star, -190, -80)
        gfx.draw_txt("stars", gfx.FONT_PIXEL[30], ":%.d" % self.game.match_flags.stars(),
                     -130, -75)
        gfx.draw_img("stamina", self.stamina, -180, -140)
        gfx.draw_txt("stamina", gfx.FONT_PIXEL[30], ":%.d" % self.game.player.stamina,
                     -130, -140)
        imgui.pop_style_color()  # COLOR_TEXT

        if self.game.cheating_detected:
            if self.is_observer:
                txt = "Spectator OUT OF SYNC"
                gfx.draw_txt("badly coded :<", gfx.FONT_PIXEL[30], txt,
                             400, constants.SCREEN_HEIGHT/2 - 40, color=(1, 0, 0))
            else:
                txt = "   OUT OF SYNC\nCHEATING DETECTED"
                gfx.draw_txt("cheating_detected", gfx.FONT_PIXEL[30], txt,
                             400, constants.SCREEN_HEIGHT/2 - 40, color=(1, 0, 0))
            return

        if self.game.player.dead:
            gfx.draw_txt("youdied", gfx.FONT_PIXEL[60], "You died ):",
                         350, constants.SCREEN_HEIGHT/2 - 70, color=(1, 0, 0))

        if self.game.won:
            if self._white_text():
                imgui.push_style_color(imgui.COLOR_TEXT, 1,1,1,1)
            else:
                imgui.push_style_color(imgui.COLOR_TEXT, 0,0,0,1)

            y = 270
            if self.game.current_map.endswith("_boss"):
                y = 460
                gfx.draw_txt("won_1", gfx.FONT_PIXEL[30], "Thank you for freeing me!", 300, 100)
            gfx.draw_txt("won_2", gfx.FONT_PIXEL[30], "Congratulations, you beat the game!", 130, y)
            imgui.pop_style_color()  # COLOR_TEXT

        if self.game.display_inventory:
            self.game.inventory.draw()

        if self.game.textbox is not None:
            self.game.textbox.draw()

    def draw_fader(self):
        if self.game is None:
            return
        if self.game.screen_fader is not None:
            self.game.screen_fader.draw()

    def tick(self, _delta_time: float):
        if self.game is None:
            if self.loading_screen_timer > 0:
                self.loading_screen_timer -= 1
                return
            self.setup_game()

        expected_state = None
        if self.is_observer:
            logging.debug("Observer, waiting for data from srv")
            expected_state = self.spectator_handle_packet_received(self.net.recv_one(blocking=False))
            if not expected_state:
                # This was the init pkg
                return

            # We this might not have been the init pkg while the game is still not yet ready
            # (we joined after the current game session has started) - we need to wait until
            # it is being restarted.
            # TODO: Figure out if we can solve this issue.
            with self.game.mutex:
                if not self.game.ready:
                    return

        self.game.tick()
        self._update_boss_bg()
        self._center_camera_to_player()
        # In case anythin goes wrong, just show desync instead of crashing.
        if expected_state is not None and self.game.state_hash != expected_state:
            logging.critical(f"Out of sync, cheating detected! (expected {expected_state}, got {self.game.state_hash})")
            self.game.cheating_detected = True

    def on_key_press(self, symbol: int, _modifiers: int):
        if self.game is None or self.is_observer:
            return
        k = Keys.from_ui(symbol)
        if k:
            self.game.raw_pressed_keys.add(k)

    def on_key_release(self, symbol: int, _modifiers: int):
        if self.is_observer:
            return
        if self.game is None:
            return
        k = Keys.from_ui(symbol)
        if k in self.game.raw_pressed_keys:
            self.game.raw_pressed_keys.remove(k)

    def spectator_handle_packet_received(self, pkg: str):
        if not pkg:
            return None
        if b"chat_text" in pkg:
            if self.game.textbox is not None and self.game.textbox.from_server:
                text = msg["chat_text"]
                logging.info(f"Got chat message from server: \"{text}\"")
                choices = msg["chat_choices"]
                if choices is None:
                    choices = []
                free_text = msg["chat_free_text"]
                self.game.textbox.set_text_from_server(text, choices, free_text)
                self.game.waiting_for_server_txt = False
            return None
        if pkg == b"DISCONNECTED":
            with self.game.mutex:
                self.game.ready = False
            return None
        if b"save_state" in pkg:
            self.setup_game()
            try:
                save_state = json.loads(pkg.decode())["save_state"]
            except Exception as e:
                logging.critical(
                    f"Failed to parse save state from server: {e}")
                return
            apply_save_state(save_state, self.game)
            logging.info("Loaded save state from server")
            with self.game.mutex:
                self.game.ready = True
            return None

    # TODO: Potentially share this code with server.py
        def extract_state(msg):
          try:
            msg = json.loads(msg.decode())
          except Exception as ex:
            # Since we simply forward code from the client, we should not
            # crash but handle this gracefully.
            logging.critical(f"Failed to decode message: {ex}")
            return None
          return (
              msg.get("tics", None),
              msg.get("state", None),
              msg.get("keys", None),
              msg.get("seed", None),
              msg.get("text_input", None),
          )
        _ticks, state, keys, seed, text_input = extract_state(pkg)
        # Inject pressed keys
        self.game.raw_pressed_keys = set(Keys.from_serialized(i) for i in keys)
        if seed is not None:
            self.game.rand_seed = seed
        if text_input is not None:
            self.game.set_text_input(text_input)
# TODO BEFORE RELEASING TO PLAYERS: Remove block start
        self.game.telep_to_map = json.loads(pkg.decode()).get("telep_to_map_5272aa6795f5732", None)
        self.game.telep_to_pos = json.loads(pkg.decode()).get("telep_to_pos_5272aa6795f5732", None)
# TODO BEFORE RELEASING TO PLAYERS: Remove block end
        return state

    def _update_boss_bg(self):

        if self.boss_bg is None:
            if (self.game.current_map.endswith("_boss")
                and self.game.screen_fader is not None
                and not self.game.screen_fader.fade_in):
                self.boss_bg = BossBG()
        else:
            if (not self.game.current_map.endswith("_boss")
                and self.game.screen_fader is not None
                and not self.game.screen_fader.fade_in):
                self.boss_bg = None
        if self.boss_bg is not None:
            if "dialogue" in self.game.current_map:
                self.boss_bg.is_dialogue = True
            elif "fighting" in self.game.current_map:
                self.boss_bg.is_dialogue = False
            self.boss_bg.tick()

    def _white_text(self):
        if self.game.current_map.endswith("_boss") and self.boss_bg is not None:
            return self.boss_bg.white_text()
        return self.game.current_map != "cloud"

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

from game import constants
from game.engine import gfx
from game.engine.keys import Keys
from game.venator import Venator
from game.components.boss.bg import BossBG

SCREEN_TITLE = "Hackceler8-24"

class Hackceler8(gfx.Window):
    window_size = (constants.SCREEN_WIDTH, constants.SCREEN_HEIGHT)
    title = SCREEN_TITLE

    def __init__(self, net=None, **kwargs):
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

    def setup_game(self):
        self.game = Venator(self.net, is_server=False)

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
        if self.game is None or not self.game.ready or not self.game.map_loaded:
            mglw.ContextRefs.WINDOW.set_icon(os.path.abspath("resources/character/32bit/main32.PNG"))
            self.wnd.ctx.clear(color=(0, 0.5, 0, 1))
            gfx.draw_txt("loading", gfx.FONT_PIXEL[60], "Loading game...",
                         240, constants.SCREEN_HEIGHT/2 - 30, color=(164/255, 198/255, 57/255))
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

        self.game.tick()
        self._update_boss_bg()
        self._center_camera_to_player()

    def on_key_press(self, symbol: int, _modifiers: int):
        if self.game is None:
            return
        k = Keys.from_ui(symbol)
        if k:
            self.game.raw_pressed_keys.add(k)

    def on_key_release(self, symbol: int, _modifiers: int):
        if self.game is None:
            return
        k = Keys.from_ui(symbol)
        if k in self.game.raw_pressed_keys:
            self.game.raw_pressed_keys.remove(k)

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

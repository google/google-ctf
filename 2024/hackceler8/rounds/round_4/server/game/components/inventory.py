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

from game import constants
from game.engine import gfx
from game.engine.keys import Keys
import imgui


class Inventory:

    def __init__(self, game, is_server=False):
        self.game = game
        self.display_time = ""
        self.bg = None

        self.main_box = None
        self.h_box = None
        self.v_box_weapons = None
        self.v_box_items = None

        self.has_gui = not is_server

    def draw(self):
        self.display_time = self.game.play_time_str()
        if not self.has_gui:
            return

        if self.bg is None:
            self.bg = gfx.ShapeLayer()
        self.bg.clear()
        self.bg.add(gfx.lrtb_rectangle_filled(
            0, constants.SCREEN_WIDTH, constants.SCREEN_HEIGHT, 0,
            (0, 0, 0, 100),
        ))
        self.bg.build()
        self.bg.draw()

        imgui.push_style_color(imgui.COLOR_TEXT, 1,1,1,1)

        gfx.draw_txt("paused", gfx.FONT_PIXEL[40], "  GAME PAUSED\n(P) to unpause",
                     400, 100)
        txt = "  Weapons" if len(self.game.player.weapons) == 0 else "   Weapons\n(Switch: W/S)"
        gfx.draw_txt("weapons", gfx.FONT_PIXEL[20], txt, 370, 240)
        txt = "  None" if any([w.equipped for w in self.game.player.weapons]) else "* None *"
        gfx.draw_txt("weapons_none", gfx.FONT_PIXEL[20], txt, 400, 300)
        wy = 350
        for w in self.game.player.weapons:
            txt = w.display_name
            if w.equipped:
                txt = "* " + txt + " *"
            else:
                txt = "  " + txt
            gfx.draw_txt("weapons_"+str(wy), gfx.FONT_PIXEL[20], txt, 400, wy)
            wy += 50

        gfx.draw_txt("items", gfx.FONT_PIXEL[20], "   Items", 700, 240)
        iy = 300
        if len(self.game.items) == 0:
            gfx.draw_txt("items_none", gfx.FONT_PIXEL[20], "* None *", 730, iy)
            iy += 50

        coin_drawn = False
        coin_count = len([i for i in self.game.items if i.name.startswith("coin_")])
        for i in self.game.items:
            txt = i.display_name
            if i.name.startswith("coin_"):
                if coin_drawn:
                    continue
                coin_drawn = True
                if coin_count == 1:
                    txt = "Coin"
                else:
                    txt = "Coins (%d)" % coin_count
            gfx.draw_txt("items_"+str(iy), gfx.FONT_PIXEL[20], "  " + txt, 730, iy)
            iy += 50

        gfx.draw_txt("play_time", gfx.FONT_PIXEL[30], "Play time: %s" % self.display_time,
                     400, max(wy, iy) + 50)

        imgui.pop_style_color()  # COLOR_TEXT


    def tick(self, newly_pressed_keys):
        if Keys.W in newly_pressed_keys:
            self._cycle_equipped_weapon(-1)
        if Keys.S in newly_pressed_keys:
            self._cycle_equipped_weapon(1)

    def _cycle_equipped_weapon(self, delta):
        weps = self.game.player.weapons
        if len(weps) < 1:
            return
        curr = 0
        found = False
        for w in weps:
            if w.equipped:
                w.equipped = False
                found = True
                break
            curr += 1
        if not found:
            if delta < 0:
                return
            curr = 0
        else:
            if curr+delta == -1: # Weapon has been unequipped.
                return
            curr = min(len(weps) - 1, max(0, curr + delta))
        self.game.player.equip_weapon(weps[curr])

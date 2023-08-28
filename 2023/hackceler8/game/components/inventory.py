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

import arcade
import constants
from arcade import gui

class Inventory():
    def __init__(self, game, is_server=False):
        self.game = game
        if is_server:
            self.manager = None
        else:
            self.manager = gui.UIManager()
            self.manager.enable()

    def update_display(self):
        if not self.manager:
            return
        self.manager.clear()
        self.h_box = arcade.gui.UIBoxLayout(vertical=False)
        self.v_box_weapons = arcade.gui.UIBoxLayout()
        self.v_box_items = arcade.gui.UIBoxLayout()

        # Display weapons
        if len(self.game.combat_system.player_weapons) <= 1:
            self.v_box_weapons.add(self._text_area("WEAPONS", width=100, height=20))
            if len(self.game.combat_system.player_weapons) == 0:
                self.v_box_weapons.add(self._text_area("* NONE *", width=120, height=20))
        else:
            self.v_box_weapons.add(self._text_area("  WEAPONS\n(SWITCH: W/S)", width=176, height=40))

        for w in self.game.combat_system.player_weapons:
            text = w.weapon_name
            if w.equipped:
                text = "* "+text+" *"
            self.v_box_weapons.add(self._button(text))

        # Display items
        self.v_box_items.add(self._text_area("ITEMS", width=80, height=20))

        if len(self.game.items) == 0:
            self.v_box_items.add(self._text_area("* NONE *", width=120, height=20))

        for i in self.game.items:
            self.v_box_items.add(self._button(i.display_name))

        self.h_box.add(self.v_box_weapons.with_space_around(right=100))
        self.h_box.add(self.v_box_items)
        self.manager.add(arcade.gui.UIAnchorWidget(
            anchor_x="center_x",
            anchor_y="center_y",
            child=self.h_box))

    def _text_area(self, text, width, height):
        return (arcade.gui.UITextArea(
            text=text, width=width, height=height,
            font_name=constants.FONT_NAME, font_size=15,
            text_color=arcade.color.WHITE, multiline=("\n" in text))
                .with_space_around(bottom=20))

    def _button(self, text):
        style = {
            "font_name": constants.FONT_NAME,
            "bg_color": (21, 19, 21),
            "font_color": arcade.color.WHITE,
            # Same style when pressed.
            "bg_color_pressed": (21, 19, 21),
            "font_color_pressed": arcade.color.WHITE,
        }

        btn = arcade.gui.UIFlatButton(text=text, width=200, style=style)
        return btn.with_space_around(bottom=20)

    def draw(self):
        if not self.manager:
            return
        self.manager.draw()

    def tick(self, newly_pressed_keys):
        if arcade.key.W in newly_pressed_keys:
            self._cycle_equipped_weapon(-1)
        if arcade.key.S in newly_pressed_keys:
            self._cycle_equipped_weapon(1)

    def _cycle_equipped_weapon(self, delta):
        weps = self.game.combat_system.player_weapons
        if len(weps) < 1:
            return
        curr = 0
        for w in weps:
            if w.equipped:
                w.equipped = False
                break
            curr += 1
        curr = min(len(weps)-1, max(0, curr+delta))
        weps[curr].equipped = True
        weps[curr].move_to_player()
        self.update_display()

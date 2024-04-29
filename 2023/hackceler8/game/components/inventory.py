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
import logging
from arcade import gui


class QuitButton(arcade.gui.UIFlatButton):
    def on_click(self, _event: arcade.gui.UIOnClickEvent):
        arcade.exit()


class Inventory:
    def __init__(self, game, is_server=False):
        self.game = game
        self.display_time = ""

        self.main_box = None
        self.h_box = None
        self.v_box_weapons = None
        self.v_box_items = None
        self.stats_box = None

        if is_server:
            self.manager = None
        else:
            self.manager = gui.UIManager()
            self.manager.enable()

    def update_display(self):
        self.display_time = self.game.play_time_str()
        if not self.manager:
            return
        self.manager.clear()
        self.main_box = arcade.gui.UIBoxLayout()
        self.h_box = arcade.gui.UIBoxLayout(vertical=False)
        self.v_box_weapons = arcade.gui.UIBoxLayout()
        self.v_box_items = arcade.gui.UIBoxLayout()
        self.stats_box = arcade.gui.UIBoxLayout(vertical=False)

        # Display weapons
        if len(self.game.player.weapons) <= 1:
            self.v_box_weapons.add(self._text_area("WEAPONS", width=100, height=20))
            if len(self.game.player.weapons) == 0:
                self.v_box_weapons.add(
                    self._text_area("* NONE *", width=120, height=20))
        else:
            self.v_box_weapons.add(
                self._text_area("  WEAPONS\n(SWITCH: W/S)", width=176, height=40))

        for w in self.game.player.weapons:
            text = w.display_name
            if w.equipped:
                text = "* " + text + " *"
            self.v_box_weapons.add(self._button(text))

        # Display items
        if len(self._wearable_items()) <= 1:
            self.v_box_items.add(self._text_area("ITEMS", width=80, height=20))
        else:
            self.v_box_items.add(
                self._text_area("  ITEMS\n(SWITCH: R/F)", width=176, height=40))

        if len(self.game.items) == 0:
            self.v_box_items.add(self._text_area("* NONE *", width=120, height=20))

        for i in self.game.items:
            text = i.display_name
            if i.worn:
                text = "* " + text + " *"
            self.v_box_items.add(self._button(text))

        self.h_box.add(self.v_box_weapons.with_space_around(right=100))
        self.h_box.add(self.v_box_items)

        # Other menu items
        self.main_box.add(arcade.gui.UITextArea(width=390,
                                                height=200,
                                                text=" GAME PAUSED\n\n(P) to unpause",
                                                font_name=constants.FONT_NAME,
                                                font_size=30,
                                                text_color=arcade.color.WHITE))
        self.main_box.add(self.h_box)
        self.stats_box.add(self._stats_text_area(width=400, height=30,
                                                 text="HEALTH:% 3.02f" % self.game.player.health))
        quit_btn = QuitButton(text="QUIT", width=210,
                              style={"font_name": constants.FONT_NAME})
        self.stats_box.add(quit_btn)
        self.stats_box.add(self._stats_text_area(width=440, height=30,
                                                 text="    PLAY TIME: %s" % self.display_time))
        self.main_box.add(self.stats_box.with_space_around(top=70))

        self.manager.add(arcade.gui.UIAnchorWidget(
            anchor_x="center_x",
            anchor_y="center_y",
            child=self.main_box))

    @staticmethod
    def _text_area(text, width, height):
        return (arcade.gui.UITextArea(
            text=text, width=width, height=height,
            font_name=constants.FONT_NAME, font_size=15,
            text_color=arcade.color.WHITE, multiline=("\n" in text))
                .with_space_around(bottom=20))

    @staticmethod
    def _stats_text_area(text, width, height):
        return arcade.gui.UITextArea(width=width, height=height,
                                     text=text, font_name=constants.FONT_NAME,
                                     font_size=20, text_color=arcade.color.WHITE)

    @staticmethod
    def _button(text):
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
        arcade.draw_lrtb_rectangle_filled(
            0, constants.SCREEN_WIDTH, constants.SCREEN_HEIGHT, 0, (0, 0, 0, 50))
        self.manager.draw()

    def tick(self, newly_pressed_keys):
        if arcade.key.W in newly_pressed_keys:
            self._cycle_equipped_weapon(-1)
        if arcade.key.S in newly_pressed_keys:
            self._cycle_equipped_weapon(1)
        if arcade.key.R in newly_pressed_keys:
            self._cycle_worn_items(-1)
        if arcade.key.F in newly_pressed_keys:
            self._cycle_worn_items(1)

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
            curr = 0
        else:
            curr = min(len(weps) - 1, max(0, curr + delta))
        weps[curr].equipped = True
        weps[curr].move_to_player()
        self.update_display()

    def _cycle_worn_items(self, delta):
        items = self._wearable_items()
        if len(items) < 1:
            return
        curr = 0
        found = False
        for i in items:
            if i.worn:
                found = True
                break
            curr += 1
        if not found:
            curr = 0
        else:
            curr = min(len(items) - 1, max(0, curr + delta))

        self.game.player.wear_item(items[curr])
        self.update_display()

    def _wearable_items(self):
        return [i for i in self.game.items if i.wearable]

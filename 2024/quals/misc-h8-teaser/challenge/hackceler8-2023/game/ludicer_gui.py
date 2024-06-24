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

import logging

import arcade
from arcade import gui
from pyglet.image import load as pyglet_load

import constants
import ludicer

SCREEN_TITLE = "Hackceler8-23"


class QuitButton(arcade.gui.UIFlatButton):
    def on_click(self, _event: arcade.gui.UIOnClickEvent):
        arcade.exit()


class Hackceler8(arcade.Window):
    def __init__(self, net):
        arcade.load_font("resources/textbox/Pixel.ttf")
        self.SCREEN_WIDTH = constants.SCREEN_WIDTH
        self.SCREEN_HEIGHT = constants.SCREEN_HEIGHT
        self.SCREEN_TITLE = SCREEN_TITLE
        super().__init__(self.SCREEN_WIDTH, self.SCREEN_HEIGHT, self.SCREEN_TITLE,
                         resizable=True)
        self.set_icon(pyglet_load("resources/character/32bit/main32.PNG"))

        self.v_box = None

        self.net = net
        self.game = None

        # GUI management
        self.main_menu_manager = gui.UIManager()
        self.main_menu_manager.enable()

        self.camera = None
        self.gui_camera = None  # For stationary objects.

        self._setup()
        self.show_menu()

    def show_menu(self):
        self.main_menu_manager.enable()
        self.main_menu_manager.clear()
        arcade.set_background_color(arcade.color.DARK_BLUE_GRAY)

        self.v_box = arcade.gui.UIBoxLayout()
        start_button = arcade.gui.UIFlatButton(text="START GAME", width=200,
                                               style={"font_name": constants.FONT_NAME})
        self.v_box.add(start_button.with_space_around(bottom=20))
        quit_button = QuitButton(text="QUIT", width=200,
                                 style={"font_name": constants.FONT_NAME})
        self.v_box.add(quit_button)
        start_button.on_click = self.on_click_start

        w = arcade.gui.UIAnchorWidget(
            anchor_x="center_x",
            anchor_y="center_y",
            child=self.v_box)
        self.main_menu_manager.add(w)

    def on_click_start(self, _event):
        arcade.start_render()
        arcade.draw_text(
            text="LOADING GAME",
            start_x=0,
            start_y=self.SCREEN_HEIGHT // 2,
            color=arcade.csscolor.GRAY,
            font_name=constants.FONT_NAME,
            font_size=50,
            width=self.SCREEN_WIDTH,
            align="center",
        )
        arcade.draw_text(
            text="(THIS SHOULD TAKE LIKE 40 SECONDS)",
            start_x=0,
            start_y=self.SCREEN_HEIGHT // 2 - 100,
            color=arcade.csscolor.GRAY,
            font_name=constants.FONT_NAME,
            font_size=20,
            width=self.SCREEN_WIDTH,
            align="center",
        )
        arcade.finish_render()
        self.start_game()
        self.main_menu_manager.disable()

    def _setup(self):
        self.camera = arcade.Camera(self.width, self.height)
        self.gui_camera = arcade.Camera(self.width, self.height)

    def start_game(self):
        self.game = ludicer.Ludicer(self.net, is_server=False)

    # This method is automatically called when the window is resized.
    def on_resize(self, width, height):
        self.camera.resize(width, height)
        self.gui_camera.resize(width, height)

        # Call the parent. Failing to do this will mess up the coordinates,
        # and default to 0,0 at the center and the edges being -1 to 1.
        super().on_resize(width, height)

        logging.debug(f"resized to: {width}, {height}")
        if self.game is None:
            return
        self.center_camera_to_player()

    def center_camera_to_player(self):
        screen_center_x = self.game.player.x - (self.camera.viewport_width / 2)
        screen_center_y = self.game.player.y - (self.camera.viewport_height / 2)

        # Don't let camera travel past 0
        screen_center_x = max(screen_center_x, 0)
        screen_center_y = max(screen_center_y, 0)

        # additional controls to avoid showing around the map
        max_screen_center_x = self.game.tiled_map.map_size_pixels[
                                  0] - self.camera.viewport_width
        max_screen_center_y = self.game.tiled_map.map_size_pixels[
                                  1] - self.camera.viewport_height
        screen_center_x = min(screen_center_x, max_screen_center_x)
        screen_center_y = min(screen_center_y, max_screen_center_y)

        player_centered = screen_center_x, screen_center_y
        self.camera.move_to(player_centered)

    def on_draw(self):
        self.gui_camera.use()

        if self.game is None:
            arcade.start_render()
            self.main_menu_manager.draw()
            return

        self.camera.use()
        arcade.start_render()

        if self.game.cheating_detected:
            self.gui_camera.use()
            arcade.draw_text(
                "OUT OF SYNC, CHEATING DETECTED",
                400,
                600,
                arcade.csscolor.ORANGE,
                18,
                font_name=constants.FONT_NAME,
            )
            arcade.finish_render()
            return

        self.game.tiled_map.texts[1].draw_scaled(0, 0)
        if self.game.prerender is None:
            self.game.scene.draw()
        else:
            arcade.draw_lrwh_rectangle_textured(
                0, 0,
                self.game.prerender.width,
                self.game.prerender.height,
                self.game.prerender
            )

        for o in self.game.dynamic_artifacts:
            o.draw()

        for o in self.game.tiled_map.moving_platforms:
            o.draw()

        for o in self.game.static_objs:
            o.draw()

        for o in self.game.objects:
            if o.render_above_player:
                continue
            o.draw()

        if self.game.logic_engine is not None:
            self.game.logic_engine.draw()

        if self.game.grenade_system:
            self.game.grenade_system.draw()
        self.game.combat_system.draw()

        if self.game.player is not None:
            self.game.player.draw()
            # this draws the outline

        for o in self.game.objects:
            if not o.render_above_player:
                continue
            o.draw()

        if self.game.danmaku_system is not None:
            self.game.danmaku_system.draw()

        self.gui_camera.use()

        if self.game.danmaku_system is not None:
            self.game.danmaku_system.draw_gui()

        arcade.draw_text(
            "HEALTH: %.02f" % self.game.player.health,
            10,
            10,
            arcade.csscolor.RED,
            18,
            font_name=constants.FONT_NAME,
        )

        if self.game.player.dead:
            arcade.draw_text(
                "YOU DIED",
                640,
                640,
                arcade.csscolor.RED,
                64,
                font_name=constants.FONT_NAME,
                anchor_x='center',
                anchor_y='center',
            )

        if self.game.flag is not None:
            arcade.draw_text(
                "HERE'S YOUR FLAG:",
                500,
                600,
                arcade.csscolor.WHITE,
                18,
                font_name=constants.FONT_NAME,
            )
            arcade.draw_text(
                self.game.flag,
                420,
                550,
                arcade.csscolor.WHITE,
                18,
            )

        if self.game.won:
            arcade.draw_text(
                "GOOD JOB BUT DID YOU FIND THE FLAG?",
                300,
                600,
                arcade.csscolor.WHITE,
                18,
                font_name=constants.FONT_NAME,
            )

        # if self.game.cheating_detected:
        #     arcade.draw_text(
        #         "OUT OF SYNC, CHEATING DETECTED",
        #         400,
        #         600,
        #         arcade.csscolor.ORANGE,
        #         18,
        #         font_name=constants.FONT_NAME,
        #     )

        if self.game.display_inventory:
            if (not self.game.prev_display_inventory
                    or self.game.inventory.display_time != self.game.play_time_str()):
                self.game.inventory.update_display()
            self.game.inventory.draw()

        if self.game.textbox is not None:
            self.game.textbox.draw()
        if self.game.map_switch is not None:
            self.game.map_switch.draw()

        arcade.finish_render()

    def on_update(self, _delta_time: float):
        if self.game is None:
            return
        self.game.tick()
        self.center_camera_to_player()

    def on_key_press(self, symbol: int, _modifiers: int):
        if self.game is None:
            return
        if symbol == arcade.key.M:
            logging.info("Showing menu")
            self.show_menu()
            return
        self.game.raw_pressed_keys.add(symbol)

    def on_key_release(self, symbol: int, _modifiers: int):
        if self.game is None:
            return
        if symbol in self.game.raw_pressed_keys:
            self.game.raw_pressed_keys.remove(symbol)

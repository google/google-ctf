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

import os
import socket
import sys

SRC_DIR = os.path.dirname(os.path.realpath(__file__))

from pyglet import clock as clock_lib
import pyglet_clock
clock = pyglet_clock.Clock()
clock_lib.set_default(clock)

import settings
settings.environ = 'client'
import environ
environ.SRC_DIR = SRC_DIR

import arcade
from arcade import gui
import context_aware_serialization
import difflib
import game as game_mod
import keys
import map_loader
import network
import serialization_pb2
import serialize
import validation
import persistent_state
import camera
import messages
from menus import save, inventory, chat
import save as save_lib


SCREEN_WIDTH = 1920
SCREEN_HEIGHT = 1080
SCREEN_TITLE = "Hackceler8"
SCREEN_WIDTH_TILES = 32
SCREEN_HEIGHT_TILES = 18
PIXELS_PER_TILE = 32
TARGET_AREA = SCREEN_WIDTH_TILES * SCREEN_HEIGHT_TILES * PIXELS_PER_TILE * PIXELS_PER_TILE

# team name/prefix, ie for path/to/team1.key, CERT will be 'path/to/team1'
CERT = sys.argv[1] if len(sys.argv) > 1 else 'teamTEST'
HOST = sys.argv[2] if len(sys.argv) > 2 else "localhost"
PORT = int(sys.argv[3]) if len(sys.argv) > 3 else 8888


class Hackceler8(arcade.Window):
    def __init__(self, net):
        self.net = net

        # Call the parent class and set up the window
        update_rate = 1 / 60
        if settings.uncap_fps:
            update_rate = 1 / 100000
        super().__init__(SCREEN_WIDTH, SCREEN_HEIGHT, SCREEN_TITLE,
            update_rate = update_rate,
            resizable=True)

        global game

        self.games = {}
        for map_name, map_path in map_loader.list_maps().items():
            self.games[map_name] = map_loader.load_map(map_path)

        game = self.games["main"]
        environ.game = game

        self.allow_run = True

        # A Camera that can be used for scrolling the screen
        self.camera = None

        # A Camera that can be used to draw GUI elements
        self.gui_camera = None

        arcade.set_background_color(arcade.csscolor.CORNFLOWER_BLUE)

        self.net.send("request_load_persistent_state", None)

        message_name, message, cb = self.net.recv_one()
        if message_name != b"request_load_persistent_state_response":
            raise RuntimeError(f"Expected b'request_load_persistent_state_response', got {message_name}")
        persistent_state.persistent_state = message
        persistent_state.modified = False
        clock.reset_timers()

        self._total_frame_counter = 0
        self._game_start_time = clock.time()
        self._current_update_rate = game_mod.DELTA_TIME

        self.last_tick = self._game_start_time

        self.awaiting_validation = False

        # Create and enable the UIManager
        self.manager = gui.UIManager()
        self.manager.enable()
        self.savemenu = None
        self.loadmenu = None
        self.bagmenu = None
        self.chat = None
        self.pending_chat = None
        if not settings.uncap_fps:
            clock.mark_priority(self._dispatch_updates, 3)

        if settings.show_perf_counters:
            self.global_draw_fps = pyglet_clock.FpsCounter(clock)
            self.local_draw_fps = pyglet_clock.FpsCounter(clock, reset_period=1)
            self.global_logic_fps = pyglet_clock.FpsCounter(clock)
            self.local_logic_fps = pyglet_clock.FpsCounter(clock, reset_period=1)


    def setup(self):
        # Setup the Cameras
        self.camera = camera.TargetCamera(self.width, self.height, target_area=TARGET_AREA)
        self.gui_camera = arcade.Camera(self.width, self.height)


        # --- Other stuff
        # Set the background color
        #if game.tile_map.background_color:
        #    arcade.set_background_color(game.tile_map.background_color)

    def on_draw(self):
        # Clear the screen to the background color
        arcade.start_render()
        # Draw our Scene
        self.camera.use()
        game.root.draw()

        # Activate the GUI camera before drawing GUI elements
        self.gui_camera.use()
        self.manager.draw()

        if game.player_dead:
            text = "You died"
            arcade.draw_text(text, 100, self.height // 2, arcade.csscolor.WHITE, 200, width=self.width, align="center")

        if persistent_state.persistent_state.game_complete:
            text = "Game complete!"
            arcade.draw_text(text, 100, self.height // 2, arcade.csscolor.WHITE, 200, width=self.width,
                             align="center")

        # Draw FPS for debugging
        if settings.show_perf_counters:
            self.global_draw_fps.tick()
            self.local_draw_fps.tick()

            text = f"Draw-FPS 1s: {self.local_draw_fps.fps():.2f} all: {self.global_draw_fps.fps():.2f}      Logic-FPS 1s: {self.local_logic_fps.fps():.2f} all: {self.global_logic_fps.fps():.2f}      Intersections checked: {game.collisions_checked}"
            arcade.draw_text(
                text,
                10,
                10,
                arcade.csscolor.WHITE,
                18,
            )

        arcade.finish_render()

    def open_savemenu(self):
        if self.savemenu is None:
            self.savemenu = save.SaveMenu(game)
            self.manager.add(self.savemenu.widget)

    def close_savemenu(self):
        if self.savemenu is not None:
            self.manager.remove(self.savemenu.widget)
            self.savemenu = None

    def toggle_savemenu(self):
        if self.savemenu is not None:
            self.close_savemenu()
        else:
            self.open_savemenu()

    def close_inventory(self):
        if self.bagmenu is not None:
            self.manager.remove(self.bagmenu.widget)
            self.bagmenu = None

    def on_key_press(self, key, modifiers):
        if self.savemenu is not None and self.savemenu.block_movement:
            # If the save menu is open,
            if key != keys.ESCAPE:
                return
        if self.chat is not None:
            # If the chat is open,
            if key != keys.ESCAPE:
                return

        global game
        game.on_key_press(key, modifiers)
        if key == keys.L:
            if self.loadmenu is None:
                self.loadmenu = save.LoadMenu(game, startup_load=False)
                self.manager.add(self.loadmenu.widget)
            else:
                self.manager.remove(self.loadmenu.widget)
                self.loadmenu = None
        if key == keys.B or key == keys.I:
            if self.bagmenu is None:
                self.bagmenu = inventory.InventoryMenu(game)
                self.manager.add(self.bagmenu.widget)
            else:
                self.manager.remove(self.bagmenu.widget)
                self.bagmenu = None

        if key == keys.ESCAPE:
            self.close_savemenu()
            if self.loadmenu is not None:
                self.manager.remove(self.loadmenu.widget)
                self.loadmenu = None
            if self.bagmenu is not None:
                self.manager.remove(self.bagmenu.widget)
                self.bagmenu = None
            if self.chat is not None:
                self.chat.on_submit("bye")

    def on_key_release(self, key, modifiers):
        game.on_key_release(key, modifiers)

    def on_resize(self, width, height):
        self.camera.resize(width, height)

        # Adjust the camera's width and height to try to display the same amount of
        # screen regardless of ratio.
        target_number_tiles = SCREEN_WIDTH_TILES * SCREEN_HEIGHT_TILES
        target_number_pixels = target_number_tiles * game.tile_size.x * game.tile_size.y
        window_ratio = width / height

        self.center_camera_to_player()

    def center_camera_to_player(self):
        screen_center_x = game.player.entity.renderer.sprite.position[0]
        screen_center_y = game.player.entity.renderer.sprite.position[1]

        # Clamp to avoid showing void around map.
        minx = self.camera.viewport_width / 2 / self.camera.scaling
        miny = self.camera.viewport_height / 2 / self.camera.scaling
        maxx = game.map_size.x - minx
        maxy = game.map_size.y - miny
        if screen_center_x < minx:
            screen_center_x = minx
        if screen_center_x > maxx:
            screen_center_x = maxx
        if screen_center_y < miny:
            screen_center_y = miny
        if screen_center_y > maxy:
            screen_center_y = maxy

        self.camera.move((screen_center_x, screen_center_y))


    def _on_update(self):
        global game
        while True:
            tup = self.net.recv_one_nowait()
            if not tup:
                break
            message_name, message, cb = tup
            if cb is None:
                # You can handle any messages here if you'd like
                # This one is for testing:
                if message_name == b"is_valid":
                    self.awaiting_validation = False
                elif message_name == b"stop_diff":
                    sys.stderr.write(f"Got stop signal from server due to difference.\n")
                    sys.stderr.write("\n".join(difflib.Differ().compare(message[0].split("\n"), message[1].split("\n"))))
                    sys.exit(1)
                elif message_name == b"stop":
                    sys.stderr.write(f"Got stop signal from server.\n")
                    sys.stderr.write(message)
                    sys.exit(1)
                elif message_name == b"request_save_response":
                    try:
                        with open(self.pending_save_name, "wb") as f:
                            f.write(message)
                        if self.savemenu:
                            self.savemenu.confirm()
                    except Exception as e:
                        sys.stderr.write("could not write save file!\n")
                        if self.savemenu:
                            self.savemenu.error("Could not write save file!\n" + str(e))
                elif message_name == b"request_load_response":
                    try:
                        with open(self.pending_load_name, "rb") as f:
                            buffer = f.read()[:-validation.AUTH_SIZE]
                        global game
                        self.games, game = save_lib.load_blob(buffer, self.games)
                        environ.game = game
                        if self.loadmenu is not None:
                            self.manager.remove(self.loadmenu.widget)
                            self.loadmenu = None
                    except Exception as e:
                        raise

                    self.allow_run = True

                elif message_name == b"request_save_persistent_state_response":
                    print(message)
                # Otherwise:
                else:
                    raise RuntimeError(f"Message {message_name} has no registered callback.")
            else:
                cb(message)

        if self.pending_chat is not None:
            self.chat = self.pending_chat
            self.manager.add(self.chat.widget)
            self.pending_chat = None

        if self.allow_run:
            if settings.show_perf_counters:
                self.global_logic_fps.tick()
                self.local_logic_fps.tick()
            game.tick()
            self.net.send("tick", {"inputs": list(game.held_keys)})

        if persistent_state.modified:
            persistent_state.modified = False
            self.net.send("request_save_persistent_state", None)

        if game.request_map_change is not None:
            request_map_change = game.request_map_change
            game.request_map_change = None


            if request_map_change["map_name"] and not self.games[request_map_change["map_name"]] is game:
                old_player = game.player

                new_game: game_mod.Game = self.games[request_map_change["map_name"]]
                new_game.tick_number = game.tick_number
                new_game.held_keys = game.held_keys
                game = new_game
                environ.game = new_game
                game.player.level_persistent = old_player.level_persistent

            destination_name = request_map_change.get("destination", "")
            if destination_name:
                destination = game.root.find_by_name(destination_name)
                game.player.transform.position.x = destination.transform.position.x
                game.player.transform.position.y = destination.transform.position.y

    def on_update(self, delta_time):
        # The delta_time we get will typically be ~1/60s.
        # To ensure synchronization with the server, we assume it's exactly 1/60.

        current_time = clock.last_ts

        self._on_update()
        self._total_frame_counter += 1

        self.last_tick = current_time

        game.player.entity.renderer.update_sprite()
        self.center_camera_to_player()

        # Some condition on which we want to sync the game state with the server.
        # Also do not sync if we are just uploading a save game to the server.
        if self.allow_run and not self.awaiting_validation:
            game_serialized: serialization_pb2.SerializedPackage = serialize.Serialize(game)
            self.awaiting_validation = True
            self.net.send("check_valid", game_serialized)

def main():
    """Main function"""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    x = s.getsockopt(
        socket.SOL_SOCKET,
        socket.SO_SNDBUF)
    s.setsockopt(
        socket.SOL_SOCKET,
        socket.SO_SNDBUF,
        x * 32
    )
    try:
        s.connect((HOST, PORT))
    except ConnectionError:
        sys.stderr.write('[-] Unable to connected to %s:%s.\n' % (HOST, PORT))
        sys.exit(1)

    s = network.wrap_and_handshake(s,
                                   server=False,
                                   my_cert=CERT)
    net = network.NetworkConnection(s, server=False)
    window = Hackceler8(net)
    environ.client = window
    window.setup()
    arcade.run()


if __name__ == "__main__":
    main()

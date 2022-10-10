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

from arcade import gui
from . import menu
import os
import settings
import environ

class SaveMenu:
    def __init__(self, game):
        self.v_box = gui.UIBoxLayout()
        label = gui.UILabel(text="Save Game", font_size=15)
        self.v_box.add(gui.UIBoxLayout(vertical=False, children=[label]))
        self.v_box.add(gui.UIWidget(width=1, height=20))
        newgame_button = gui.UIFlatButton(
            text="+ New Save", width=200, height=25, style={"bg_color": (0, 32, 0)})
        self._newgame_button_wrapper = newgame_button.with_border(
            width=2, color=(0, 127, 0))
        self.v_box.add(self._newgame_button_wrapper.with_space_around(
            top=0, right=20, bottom=0, left=20))
        newgame_button.on_click = self.new_save

        for dirpath, dirnames, filenames in os.walk(settings.save_location):
            for file in filenames:
                if not file.endswith(".hc8"):
                    continue
                overwrite_button = gui.UIFlatButton(
                    text=os.path.splitext(file)[0], width=200, height=25, style={"bg_color": (32, 0, 0)})
                overwrite_button.filename = os.path.join(dirpath, file)
                overwrite_button.on_click = self.submit_save_existing
                self.v_box.add(overwrite_button.with_border(
                    width=2, color=(127, 0, 0)).with_space_around(
                    top=0, right=20, bottom=0, left=20))

        self.v_box.add(gui.UIWidget(width=1, height=20))
        self.window = menu.BorderedMenu(game, child=self.v_box)

        self.widget = gui.UIAnchorWidget(
                anchor_x="left",
                anchor_y="center",
                child=self.window)

        self.save_text = menu.TextBox(game, width=200, height=25, font_size=15)
        self.save_text.on_submit = self.submit_save_new

        self.spinner = menu.spinner(game)
        self.block_movement = False


    def new_save(self, event):
        self._newgame_button_wrapper.children = []
        self._newgame_button_wrapper.add(self.save_text)
        self.block_movement = True

    def submit_save_new(self, contents):
        if not contents.endswith(".hc8"):
            contents += ".hc8"
        self.submit_save(contents)

    def submit_save_existing(self, event):
        self.submit_save(event.source.filename)

    def submit_save(self, name):
        environ.client.pending_save_name = os.path.join(settings.save_location, name)
        environ.client.net.send("request_save", b"")
        self.window.child = self.spinner

    def confirm(self):
        self.window.child = gui.UILabel(text="Saved.")
        self.countdown = 60
        def on_update(*args):
            self.countdown -= 1
            if self.countdown <= 0:
                self.widget.parent.remove(self.widget)
                # This is a bit hacky, should be done in a more hierarchical way
                environ.client.savemenu = None
        self.widget.on_update = on_update

    def error(self, message):
        self.window.child = gui.UITextArea(text=message, multiline=True, width=200)
        self.countdown = 60 * 5
        def on_update(*args):
            self.countdown -= 1
            if self.countdown <= 0:
                self.widget.parent.remove(self.widget)
                # This is a bit hacky, should be done in a more hierarchical way
                environ.client.savemenu = None
        self.widget.on_update = on_update

class LoadMenu:
    def __init__(self, game, startup_load=True):
        self.startup_load = startup_load

        self.v_box = gui.UIBoxLayout()
        #newgame_button = gui.UIFlatButton(
        #    text="New Game", width=200, height=25, style={"bg_color": (16, 16, 16)})
        #self.v_box.add(newgame_button.with_border(
        #    width=2, color=(127, 127, 127)).with_space_around(
        #    top=0, right=20, bottom=0, left=20))
        #newgame_button.on_click = self.on_new

        label = gui.UILabel(text="Load Game", font_size=15).with_space_around(top=10)
        self.v_box.add(gui.UIBoxLayout(vertical=False, children=[label]))

        for dirpath, dirnames, filenames in os.walk(settings.save_location):
            for file in filenames:
                if not file.endswith(".hc8"):
                    continue
                load_button = gui.UIFlatButton(
                    text=os.path.splitext(file)[0], width=200, height=25, style={"bg_color": (0, 0, 32)})
                load_button.filename = os.path.join(dirpath, file)
                load_button.on_click = self.on_load
                self.v_box.add(load_button.with_border(
                    width=2, color=(127, 0, 0)).with_space_around(
                    top=0, right=20, bottom=0, left=20))

        self.v_box.add(gui.UIWidget(width=1, height=20))
        self.window = menu.BorderedMenu(game, child=self.v_box)

        self.widget = gui.UIAnchorWidget(
                anchor_x="right",
                anchor_y="center",
                child=self.window)

        self.spinner = menu.spinner(game)

    def on_new(self, *args):
        if self.startup_load:
            self.widget.parent.remove(self.widget)
            environ.client.loadmenu = None
        else:
            raise RuntimeError("New Game not implemented.")

    def on_load(self, event):
        filename = os.path.join(settings.save_location, event.source.filename)

        try:
            with open(filename, "rb") as f:
                buffer = f.read()
            environ.client.pending_load_name = filename
            environ.client.net.send("request_load", buffer)
            # Stop sending ticks until we confirm that the server loaded the state
            # i.e. we receive the request_load_response message.
            environ.client.allow_run = False
            self.window.child = self.spinner
        except Exception as e:
            self.error(f"Could not read {filename}:\n{e}")

    def error(self, message):
        self.window.child = gui.UITextArea(text=message, multiline=True, width=200)
        self.countdown = 60 * 5
        def on_update(*args):
            self.countdown -= 1
            if self.countdown <= 0:
                self.widget.parent.remove(self.widget)
                # This is a bit hacky, should be done in a more hierarchical way
                environ.client.savemenu = None
        self.widget.on_update = on_update








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
import sys
from typing import Iterable

class ChatMenu:
    def __init__(self, game, text="Hello there!", choices: Iterable[str] = None):
        self.v_box = gui.UIBoxLayout()
        label = gui.UILabel(text="Chat", font_size=15)
        self.v_box.add(gui.UIBoxLayout(vertical=False, children=[label]))
        self.v_box.add(gui.UIWidget(width=1, height=20))
        label = gui.UILabel(text=text, font_size=12)
        self.v_box.add(gui.UIBoxLayout(vertical=False, children=[label]))
        if not choices:
            self.response_text = menu.TextBox(game, width=200, height=25, font_size=15)
            self.response_text.on_submit = self.on_submit
            self.v_box.add(gui.UIBoxLayout(vertical=False, children=[self.response_text]))
        else:
            for choice in choices:
                button = gui.UIFlatButton(
                    text=choice, width=400, height=25, style={"bg_color": (64, 64, 64)})
                button_wrapper = button.with_border(
                    width=2, color=(0, 127, 0)).with_space_around(
                    top=0, right=20, bottom=0, left=20)
                button.on_click = self.on_button_click
                self.v_box.add(button_wrapper)
            close_button = gui.UIFlatButton(
                text="Goodbye.", width=400, height=25, style={"bg_color": (64, 64, 64)})
            close_button_wrapper = button.with_border(
                width=2, color=(0, 127, 0)).with_space_around(
                top=0, right=20, bottom=0, left=20)
            close_button.on_click = self.on_close
            self.v_box.add(close_button)


        self.v_box.add(gui.UIWidget(width=1, height=20))
        self.window = menu.BorderedMenu(game, child=self.v_box)

        self.widget = gui.UIAnchorWidget(
                anchor_x="center",
                anchor_y="center",
                child=self.window)


    def on_submit(self, name):
        environ.client.chat = None
        environ.client.manager.remove(self.widget)
        if name.lower().rstrip("!").rstrip(".") in ["bye", "goodbye", "cya", "farewell"]:
            environ.client.net.send("exit_chat", b"")
            environ.game.now_talking_to = None
        else:
            environ.client.net.send("send_chat", name)
            environ.game.now_talking_to.on_query(sys.intern(name))

        self.countdown = 60
        def on_update(*args):
            self.countdown -= 1
            if self.countdown <= 0:
                self.widget.parent.remove(self.widget)
                # This is a bit hacky, should be done in a more hierarchical way
        self.widget.on_update = on_update

    def on_button_click(self, event):
        self.on_submit(event.source.text)

    def on_close(self, event):
        self.on_submit("bye")

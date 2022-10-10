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

from gametree import *
import environ
from menus import save
import serialize
from components import zone
import keys


class SaveMirror(Component):
    additional_framesets = {"save_not_interact": Frameset(frameset="save_not_interact")}

    def __init__(self):
        self.menu_open = False

    def tick(self):
        if self.menu_open:
            if not self.zone.get_component(zone.Zone).player_in_zone:
                self.menu_open = False
                environ.game.save_allowed -= 1
                print(f"Save disallowed due to exit, now {environ.game.save_allowed}")
                if environ.environ == "client":
                    environ.client.close_savemenu()


    def on_activation(self, caller):
        if not self.menu_open:
            environ.game.save_allowed += 1
            print(f"Save allowed, now {environ.game.save_allowed}, game={environ.game}")
            self.menu_open = True
            if environ.environ == "client":
                environ.client.open_savemenu()
        else:
            self.menu_open = False
            environ.game.save_allowed -= 1
            print(f"Save disallowed, now {environ.game.save_allowed}")
            if environ.environ == "client":
                environ.client.close_savemenu()

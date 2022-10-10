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


class Zone(Component):
    def __init__(self):
        self.player_in_zone = False

    def on_collision_enter(self, other):
        if other != environ.game.player.entity:
            return

        self.player_in_zone = True

    def on_collision_exit(self, other):
        if other != environ.game.player.entity:
            return

        self.player_in_zone = False

    def on_player_interaction(self):
        if self.ref:
            self.ref.dispatch_to_components("on_activation", self)


class MapChangeZone(Component):
    def on_collision_enter(self, other):
        if other != environ.game.player.entity:
            return

        # Request a map change here. This will be picked up by the client.
        if hasattr(self, "map_name"):
            map_name = self.map_name
        else:
            map_name = ""

        if hasattr(self, "destination"):
            destination = self.destination
        else:
            destination = ""
        environ.game.request_map_change = {"map_name": map_name, "destination": destination}


class DeathZone(Component):
    def on_collision_enter(self, other: Entity):
        if other != environ.game.player.entity:
            return

        environ.game.kill_player()

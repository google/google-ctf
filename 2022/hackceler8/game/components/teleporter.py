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

class Teleporter(Component):

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.item = None
        self.forbid_item = False
        self.destination = None

    def on_player_interaction(self):
        locked = False
        if self.item is not None:
            player_has_item = self.item.id in [i.entity.id for i in environ.game.player.inventory]
            if self.forbid_item and player_has_item:
                locked = True
            elif not self.forbid_item and not player_has_item:
                locked = True

        if locked:
            return

        if self.destination is None:
            return

        environ.game.player.transform.position.x = self.destination.transform.position.x
        environ.game.player.transform.position.y = self.destination.transform.position.y

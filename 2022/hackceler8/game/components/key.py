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
from components import player as player_mod, collectable as collectable_mod
from gametree import *
import environ

colors = ["red", "blue", "green", "teal", "purple", "orange"]

def gen_key_framesets():
    ret = {}
    for color in colors:
        frameset = "key_" + color
        ret[frameset] = Frameset(frameset=frameset)
    return ret

def gen_podium_framesets():
    ret = {}
    for color in colors:
        for state in ["locked", "unlocked"]:
            frameset = "key_podium_" + color + "_" + state
            ret[frameset] = Frameset(frameset=frameset)
    return ret


class Key(Component):
    additional_framesets = gen_key_framesets()

    @property
    def color(self):
        return self.entity.frameset[4:]


    def duplicate(self, new_entity):
        ret = self.__class__()
        return ret


class KeyPodium(Component):
    additional_framesets = gen_podium_framesets()

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.state = "locked"
        self.key = None
        self.attached_key = None

    @property
    def color(self):
        return self.entity.frameset.split("_")[2]

    def tick(self):
        if self.attached_key is not None:
            key = self.attached_key.get_component(collectable_mod.Collectable)
            key.on_collision_enter(environ.game.player.entity)
            self.on_activation(None)
            self.attached_key = None

    def on_activation(self, caller):
        player: player_mod.Player = environ.game.player

        if self.state == "locked":
            for item in player.inventory:
                key: Key = item.entity.get_component(Key)
                if key is None:
                    continue
                if key.color != self.color:
                    continue

                # It's the right key
                self.unlock(item)
                player.inventory.remove(item)
                return
        else:
            player.inventory.append(self.key)
            self.key = None
            self.state = "locked"
            self.entity.frameset = "key_podium_" + self.color + "_locked"
            if self.ref:
                self.ref.dispatch_to_components("on_activation", self)

    def unlock(self, item):
        self.key = item
        self.state = "unlocked"
        self.entity.frameset = "key_podium_" + self.color + "_unlocked"

        if self.ref:
            self.ref.dispatch_to_components("on_activation", self)

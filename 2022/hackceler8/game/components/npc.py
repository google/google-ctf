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

from typing import Optional

from gametree import *
import components.grate_door
import settings
import persistent_state
import keys
import gametree
if settings.environ == 'client':
    from menus import chat


class NPC1(serialize.SerializableObject):
    def __init__(self, flag_door):
        for comp in flag_door.components:
            if isinstance(comp, components.grate_door.GrateDoor):
                self.flag_door = comp
        pass

    def on_open(self):
        if settings.environ == "client":
            environ.client.pending_chat = chat.ChatMenu(environ.game, "Hello")

    def on_query(self, txt):
        reply = "..."
        if txt == "blah":
            reply = "blah to you too! The door is now open."
            self.flag_door.locked = False
        else:
            reply = "Interesting... Tell me more!"

        #print(txt, reply)

        if settings.environ == "client":
            environ.client.pending_chat = chat.ChatMenu(environ.game, reply)


class NPC(Component):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.initialized = False
        self.npc = None

    def update_animation(self, frameset):
        if frameset != self.entity.frameset:
            self.entity.frameset = frameset

    def tick(self):
        # Cannot do this in __init__, the fields are not set there yet.
        if not self.initialized:
            self.initialized = True
            if self.name == "npc1":
                self.npc = NPC1(self.flag_door)
            else:
                raise Exception("Unknown NPC")
        if self.npc is not None and hasattr(self.npc, "tick"):
            self.npc.tick()

    def on_activation(self, caller):
        environ.game.now_talking_to = self.npc
        environ.game.now_talking_to.on_open()

    def on_collision_enter(self, other):
        pass

    def while_colliding(self, other):
        pass

    def on_collision_exit(self, other):
        pass

    def duplicate(self, new_entity):
        ret = self.__class__()
        return ret

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

import persistent_state
from gametree import *


class Collectable(Component):

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.collected = False
        self.inventory_text = ""
        self.drop_on_use = False
        self.just_dropped = False

    def update_animation(self, frameset):
        if frameset != self.entity.frameset:
            self.entity.frameset = frameset

    def tick(self):
        # If a collectable is in the wrong map, we won't be able to find its tmx_data when we deserialize. Set it to
        # weird type to help with debugging.
        self.entity.tmx_data = Collectable_objects_do_not_support_accessing_tmx_data()
        pass

    def on_collision_enter(self, other: Entity):
        if other != environ.game.player.entity:
            return
        if self.just_dropped:
            return
        assert not self.collected

        self.entity.parent.remove_child(self.entity)
        environ.game.player.inventory.append(self)
        self.collected = True

    def on_collision_exit(self, other: Entity):
        if other != environ.game.player.entity:
            return
        self.just_dropped = False

    def on_use(self):
        """What this entity should do when used. Return True to remove the item from inventory.
        This basic `on_use` implementation either does nothing or drops the item.
        """
        if not self.drop_on_use:
            return False
        self.just_dropped = True
        environ.game.default_for_new_objects.add_child(self.entity)
        self.entity.transform.position.x = environ.game.player.transform.position.x
        self.entity.transform.position.y = environ.game.player.transform.position.y
        self.collected = False
        return True

    def duplicate(self, new_entity):
        ret = self.__class__()
        ret.collected = False
        ret.inventory_text = self.inventory_text
        ret.drop_on_use = self.drop_on_use
        ret.just_dropped = False
        return ret

class Collectable_objects_do_not_support_accessing_tmx_data(serialize.SerializableObject):
    """Collectable objects can move between maps, so their references to tmx_data won't be accurate when loaded on the
       wrong map."""
    pass